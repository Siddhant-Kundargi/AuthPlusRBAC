import sqlite3 as sqli3
from pymongo import MongoClient
from hashlib import sha256
from config import MONGO_CONNECTION_STRING

def mongodb_setup(mongodb_uri=MONGO_CONNECTION_STRING):
    """
    Sets up the MongoDB database with initial data if not already present.

    Args:
        mongodb_uri (str): The MongoDB connection string.

    Returns:
        MongoClient: The MongoDB client instance.
    """
    client = MongoClient(mongodb_uri)
    db = client['test']
    
    # Setup userData collection
    collection = db['userData']
    if collection.find_one({'name': 'UniversalAdmin'}) is None:
        collection.insert_one({'name': 'UniversalAdmin', 'roles': ['universal_admin', 'defaultUser']})
        
    # Setup roles collection
    collection = db['roles']
    if collection.find_one({'role': 'universal_admin'}) is None:
        collection.insert_one({
            'role': 'universal_admin', 
            'context': ['*'],
            'users': {
                'Managers': ['UniversalAdmin'],
                'Users': ['UniversalAdmin']
            },
            'transferable': True
        })

    if collection.find_one({'role': 'defaultUser'}) is None:
        collection.insert_one({
            'role': 'defaultUser', 
            'context': [],
            'users': {
                'Managers': ['UniversalAdmin'],
                'Users': ['UniversalAdmin']
            },
            'transferable': False
        })
        
    # Setup resourceData collection
    collection = db['resourceData']
    if collection.find_one({'resource': 'defaultResource'}) is None:
        collection.insert_one({'resource': 'defaultResource', 'resourceURI': 'NULL', 'resourceOwner': ['universal_admin']})

    return client

def get_mongo_conn():
    """
    Returns a MongoDB client instance with a specific connection string.

    Returns:
        MongoClient: The MongoDB client instance.
    """
    return MongoClient('mongodb://mongoadmin:secret@localhost:2717/')

def sqli_setup():
    """
    Sets up the SQLite database with initial data if not already present.

    Returns:
        sqlite3.Connection: The SQLite connection instance.
    """
    conn = sqli3.connect('database.db')
    conn.execute('CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT, email TEXT)')
    conn.commit()

    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE username = "UniversalAdmin"')
    user = cur.fetchone()
    if user is None:
        default_passwd = sha256('admin'.encode()).hexdigest()
        cur.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', ('UniversalAdmin', default_passwd, ''))
        conn.commit()

    return conn

def database_setup():
    """
    Sets up both MongoDB and SQLite databases with initial data if not already present.

    Returns:
        tuple: A tuple containing the MongoDB client instance and the SQLite connection instance.
    """
    return mongodb_setup(), sqli_setup()
