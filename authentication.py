from flask import Blueprint, request, make_response, redirect, render_template, url_for
import jwt
from hashlib import sha256
import sqlite3 as sqli3
from datetime import datetime, timedelta, timezone
from setup import get_mongo_conn
from functools import wraps
from config import JWT_SECRET

# Secret key for JWT encoding and decoding
SIG_KEY = JWT_SECRET

# Create a Blueprint for authentication routes
authentication = Blueprint('authentication', __name__)

# Get MongoDB connection
mongo_conn = get_mongo_conn()

@authentication.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handle user registration.
    On GET request, render the registration form.
    On POST request, register the user and set an authentication cookie.
    """
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        # Hash the password
        password = sha256(password.encode()).hexdigest()

        # Insert user data into SQLite database
        with sqli3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, password, email))
            con.commit()

        # Insert user data into MongoDB
        mongo_conn['test']['userData'].insert_one({'name': username, 'roles': ['defaultUser']})

        # Create a response and set the authentication cookie
        resp = make_response(redirect('/'))
        cookie_value = jwt.encode(
            {
                'exp': datetime.now(tz=timezone.utc) + timedelta(hours=1), 
                'username': username
            },
            SIG_KEY, algorithm='HS256'
        )
        resp.set_cookie('authCookie', cookie_value)
        return resp
    else: 
        # Render the registration form
        return render_template('registerUser.html')

@authentication.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handle user login.
    On GET request, render the login form.
    On POST request, authenticate the user and set an authentication cookie.
    """
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = request.form['password']
        
        # Hash the password
        password = sha256(password.encode()).hexdigest()

        # Check user credentials in SQLite database
        with sqli3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
            user = cur.fetchone()

            if user:
                # Create a response and set the authentication cookie
                resp = make_response(redirect('/'))
                cookie_value = jwt.encode(
                    {
                        'exp': datetime.now(tz=timezone.utc) + timedelta(hours=1), 
                        'username': username
                    },
                    SIG_KEY, algorithm='HS256'
                )
                resp.set_cookie('authCookie', cookie_value)
                return resp
            else:
                # Render the login form with an error message
                return render_template('login.html', error='Invalid username or password')
    else:
        # Render the login form
        return render_template('login.html')

@authentication.route('/logout')
def logout():
    """
    Handle user logout.
    Clear the authentication cookie and redirect to the home page.
    """
    resp = make_response(redirect('/'))
    resp.set_cookie('authCookie', '', expires=0)
    return resp
    
def is_authenticated(func):
    """
    Decorator to check if the user is authenticated.
    If authenticated, proceed with the original function.
    If not authenticated, redirect to the login page.
    """
    @wraps(func)
    def authentication_wrapped_function(*args, **kwargs):
        if 'authCookie' in request.cookies:
            try:
                # Decode the JWT token from the cookie
                decoded_token = jwt.decode(request.cookies['authCookie'], SIG_KEY, algorithms='HS256')
                exp_timestamp = decoded_token['exp']
                exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
                if exp_datetime > datetime.now(tz=timezone.utc):
                    # Set the username in the request and proceed with the original function
                    request.username = decoded_token['username']
                    return func(*args, **kwargs)
                else:
                    # Token has expired, redirect to login page
                    return redirect('/auth/login')   
            except jwt.ExpiredSignatureError:
                # Token has expired, redirect to login page
                return redirect('/auth/login')
        else:
            # No authentication cookie, redirect to login page
            return redirect('/auth/login')
    return authentication_wrapped_function