from flask import Flask, request, jsonify
from google.cloud import datastore

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

# Set up app and clients
app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
client = datastore.Client()

# Define constants and string templates
USERS         = 'users'
LOGIN         = 'login'
CLIENT_ID     = ''
CLIENT_SECRET = ''
DOMAIN        = ''
ALGORITHMS    = ['RS256']
ERR_400       = {'Error': 'The request body is invalid'}, 400
ERR_401       = {'Error': 'Unauthorized'}, 401
ERR_403       = {'Error': 'You don\'t have permission on this resource'}, 403
ERR_404       = {'Error': 'Not found'}, 404

# Set up OAuth client and registration
oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': "openid profile email"
    }
)

# Set up custom auth error handler class
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def verify_jwt(request):
    """
    Verify the JWT in the auth header.
    Receives a request object.
    Validates JWT and returns JWT if successful.
    Returns an AuthError if validation is unsuccessful
    """
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        return AuthError({"code": "no auth header",
                         "description": "Authorization header is missing"}, 401)
    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        return AuthError({
            "code": "invalid_header", 
            "description": "Invalid header. Use an RS256 signed JWT Access Token"
            }, 401)
    if unverified_header["alg"] == "HS256":
        return AuthError({
            "code": "invalid_header",
            "description": "Invalid header. Use an RS256 signed JWT Access Token"
        }, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            return AuthError({
                "code": "token_expired",
                "description": "token is expired"
            }, 401)
        except jwt.JWTClaimsError:
            return AuthError({
                "code": "invalid_claims",
                "description": "incorrect claims, please check the audience and issuer"
            }, 401)
        except Exception as e:
            return AuthError({
                "code": "invalid_header",
                "description": "Unable to parse authentication token, error: " + str(e)
            }, 401)
        return payload
    else:
        return AuthError({
            "code": "no_rsa_key",
            "description": "No RSA key in JWKS"
        }, 401)


@app.route('/')
def index():
    return 'Please navigate to a valid resource to use this API'


@app.route('/' + USERS + '/' + LOGIN, methods=['POST'])
def login():
    """
    Receives a username and password in the request body.
    If credentials are valid, generates a JWT.
    Returns JWT if valid, or appropriate error if not.
    """
    # Extract and validate request body
    content = request.get_json()
    if 'username' not in content or 'password' not in content:
        return ERR_400
    username, password = content['username'], content['password']
    body = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }
    headers = {"content-type": "application/json"}
    url = "https://" + DOMAIN + "/oauth/token"
    r = requests.post(url, json=body, headers=headers)
    if type(verify_jwt(r)) is AuthError:
        return ERR_401
    return r, 200


@app.route('/' + USERS, methods=['GET'])
def get_users():
    """
    Gets all users from datastore.
    Requires a valid JWT in the auth header.
    Requesting user must have admin access.
    If request is valid, returns an array of all users.
    If request is invalid, returns an appropriate error.
    """
    try:
        # Verify JWT
        payload = verify_jwt(request)
        if type(payload) is AuthError:
            return ERR_401
        # Verify user's access
        query = client.query(kind=USERS)
        query.add_filter(filter=datastore.query.PropertyFilter("sub", "=", payload['sub']))
        results = list(query.fetch())
        if results['role'] != 'admin':
            return ERR_403
        # User has valid access, query users
        query = client.query(kind=USERS)
        results = list(query.fetch())
        return results, 200
    except:
        return {'Error': 'Unable to GET users'}, 500
    

@app.route('/' + USERS + '/<int:user_id>', methods=['GET'])
def get_user_by_id(user_id):
    """
    Gets a user from datastore by the id given in the path params.
    Requires a valid JWT in the auth header.
    Requires that user is either an admin, or that user is requesting their own data.
    Returns the user's data if request is authorized.
    Raises an appropriate error if not.
    """
    try:
        # Verify JWT
        payload = verify_jwt(request)
        if type(payload) is AuthError:
            return ERR_401
        # Verify user is authorized
        query = datastore.query(kind=USERS)
        query.add_filter(datastore.query.PropertyFilter("sub", "=", payload['sub']))
        results = list(query.fetch())
        if results['role'] != 'admin' or results['sub'] != payload['sub']:
            return ERR_403
        # User is authorized, query for user
        if results['sub'] == payload['sub']:
            return results, 200
        query = datastore.query(kind=USERS)
        query.add_filter(datastore.query.PropertyFilter("id", "=", user_id))
        results = list(query.fetch())
        return results, 200
    except:
        return {'Error': f'Unable to fetch user {user_id}'}, 500
