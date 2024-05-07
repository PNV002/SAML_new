from flask import Flask, render_template, session, redirect
from functools import wraps
import pymongo

app = Flask(__name__)
# Secure the Flask application with secret key
app.secret_key = b'\xcc^\x91\xea\x17-\xd0W\x03\xa7\xf8J0\xac8\xc5'

# Database
client = pymongo.MongoClient('localhost', 27017)
db = client.user_login_system

# Decorators
def login_required(f):
    """
    Decorator to check if the user is logged in.

    :param f: The function to be wrapped
    :type f: function
    :return: The wrapped function
    :rtype: function
    """
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect('/')
    return wrap


# Routes
from user import routes
from util import request


@app.route('/')
def home():
    """
    Route for the home page.

    :return: The rendered template for the home page
    :rtype: flask.Response
    """
    return render_template('home.html')


@app.route('/dashboard/')
@login_required
def dashboard():
    """
    Route for the dashboard page.

    :return: The rendered template for the dashboard page
    :rtype: flask.Response
    """
    return render_template('dashboard.html')