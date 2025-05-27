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
CLIENT_ID = 'clientID'
CLIENT_SECRET = 'clientSecret'


# Set up app and clients
app = Flask(__name__)
client = datastore.Client()
oauth = OAuth(app)


#Error handler, adapted from: https://auth0.com/docs/quickstart/backend/python
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Format error response and append status code
# Adapted from: https://auth0.com/docs/quickstart/backend/python
def get_token_auth_header():
    """
    Obtains access token from Auth Header
    """
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({
            "code": "authorization_header_missing",
            "description": "Authorization header is expected"
        }, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({
            "code": "invalid_header",
            "description": "Authorization header must start with \"Bearer\""
        }, 401)
    elif len(parts) == 1:
        raise AuthError({
            "code": "invalid_header",
            "description": "Token not found"
        }, 401)
    elif len(parts) > 2:
        raise AuthError({
            "code": "invalid_header",
            "description": "Authorization header must be \"Bearer token\""
        }, 401)
    
    token = parts[1]
    return token


def requires_auth(f):
    """
    Determines if the access token is valid.
    Adapted from: https://auth0.com/docs/quickstart/backend/python
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        jsonurl = urlopen("https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")
        unverified_header = jwt.get_unverified_header(token)
        public_key = None
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        if public_key:
            try:
                payload = jwt.decode(
                    token,
                    public_key,
                    algorithms=ALGORITHMS,
                    audience=API_AUDIENCE,
                    issuer="https://" + AUTH0_DOMAIN + "/"
                    )
            except jwt.ExpiredSignatureError:
                raise AuthError({
                    "code": "token_expired",
                    "description": "token is expired"
                }, 401)
            except jwt.InvalidAudienceError:
                raise AuthError({
                    "code": "invalid_audience",
                    "description": "incorrect audience, please check audience"
                }, 401)
            except jwt.InvalidIssuerError:
                raise AuthError({
                    "code": "invalid_issuer",
                    "description": "incorrect issuer, please check the issuer"
                }, 401)
            except Exception:
                raise AuthError({
                    "code": "invalid_header",
                    "description": "Unable to parse auth token"
                }, 401)
            _request_ctx_stack.top_current_user = payload
            return f(*args, **kwargs)
        raise AuthError({
            "code": "invalid_header",
            "description": "Unable to find appropriate key"
        }, 401)
    return decorated


def requires_scope(required_scope):
    """
    Determines if the required scope is present in the access token
    Args: 
        required_scope(str): The scope required to access the resource
    Adapted from: https://auth0.com/docs/quickstart/backend/python
    """
    token = get_token_auth_header()
    unverified_claims = jwt.decode(token, options={"verify_signature": False})
    if unverified_claims.get("scope"):
        token_scopes = unverified_claims["scope"].split()
        for token_scope in token_scopes:
            if token_scope == required_scope:
                return True
    return False


@app.route('/')
@cross_origin(headers=["Content-Type", "Authorization"])
def index():
    return jsonify(message="Please navigate to a valid endpoint to use this app")

 
@app.route('/' + USERS + '/' + LOGIN, methods=['POST'])
def user_login():
    """
    Logs the user in.
    Requires a valid username and password in request body.
    Returns a JWT if username and password are valid.
    Returns an appropriate error if param missing or invalid user/pass.
    """
    # Extract username and password
    content = request.get_json()
    if 'username' not in content | 'password' not in content:
        return {"Error": ERR_400}, 400
    username, password = content['username'], content['password']
    # Prepare and send auth token request
    body = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }
    headers = {"content-type": "application/json"}
    url = 'http://' + AUTH0_DOMAIN + '/oauth/token'
    # Extract JWT and verify
    r = requests.post(url, json=body, headers=headers)
    if r.status_code == 401:
        return {"Error": ERR_401}, 401
    return r.text, 200, {'Content-Type': 'application/json'} 


@app.route('/' + USERS, methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def get_users():
    """
    Get all the ids, role, and auth0 token for all users.
    Requires valid JWT as bearer token in Auth header, 
    and requires user to have admin scope.
    """
    if requires_scope("admin"):
        try:
            query = client.query(
                kind=USERS,
                order=['id'],
                projection=['id', 'role', 'sub']
            )
            results = query.fetch()
        except:
            return {"Error": "Unable to fetch users"}, 500
        finally:
            return results, 200
    else:
        return {"Error": ERR_403}, 403
    

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

