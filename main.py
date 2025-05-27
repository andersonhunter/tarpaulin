from flask import Flask, request
from google.cloud import datastore
from authlib.integrations.flask_client import OAuth

# Set up app and clients
app = Flask(__name__)
client = datastore.Client()
oauth = OAuth(app)

# Define constants and string literals
USERS = "users"
LOGIN = "login"
AVATAR = "avatar"
COURSE = "course"
STUDENTS = "students"
ERR_400 = "The request body is invalid"
ERR_401 = "Unauthorized"
ERR_403 = "You don\'t have permission on this resource"
ERR_404 = "Not found"




