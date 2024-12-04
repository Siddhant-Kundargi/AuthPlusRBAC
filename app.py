from flask import Flask, render_template, request
from setup import database_setup

from authentication import authentication, is_authenticated
from authorization import authorization
from resources import resources

app = Flask(__name__)
app.register_blueprint(authentication, url_prefix='/auth')
app.register_blueprint(authorization, url_prefix='/authorize')
app.register_blueprint(resources, url_prefix='/resources')

@app.route('/', methods=['GET'])
@is_authenticated
def home():
    """
    Home route that handles GET requests.

    This route is decorated with @is_authenticated to ensure that only authenticated users can access it.
    It renders the 'home.html' template and passes the username from the request to the template.

    Returns:
        Response: The rendered 'home.html' template with the username context.
    """
    return render_template('home.html', username=request.username)

if __name__ == '__main__':
    
    database_setup()
    app.run(host='127.0.0.1', port=8000, debug=False)