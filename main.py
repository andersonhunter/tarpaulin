#Imports
from flask import Flask, request, jsonify, _request_ctx_stack
from flask_cors import cross_origin
import jwt
from google.cloud import datastore
from authlib.integrations.flask_client import OAuth
import json
from six.moves.urllib.request import urlopen
from functools import wraps

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
AUTH0_DOMAIN = '{theDomain}'
API_AUDIENCE = 'theAudience'
ALGORITHMS = ["RS256"]


# Set up app and clients
app = Flask(__name__)
client = datastore.Client()
oauth = OAuth(app)


#Error handler, adapted from: https://auth0.com/docs/quickstart/backend/python
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@APP.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

