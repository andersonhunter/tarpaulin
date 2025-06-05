from flask import Flask, request, jsonify, send_file
from google.cloud import datastore
from google.cloud import storage

import requests
import json
import io

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

# Set up app and clients
app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
client = datastore.Client()

# Define constants and string templates
PORT = 8080
USERS = 'users'
LOGIN = 'login'
COURSES = 'courses'
AVATAR = 'avatar'
STUDENTS = 'students'
CLIENT_ID = 'dAfIo7IWppXjCCs6qi6FQuLiiGy5C0yP'
CLIENT_SECRET = '4RT8rnDPEkwOthpW3e72qixxGeR4Q89h_BR4IzWRruGSQW6htcJjDb4C2U4FbTu-'
DOMAIN = 'dev-1eddc7qebeobiwsf.us.auth0.com'
ALGORITHMS = ['RS256']
ERR_400 = {'Error': 'The request body is invalid'}, 400
ERR_401 = {'Error': 'Unauthorized'}, 401
ERR_403 = {'Error': 'You don\'t have permission on this resource'}, 403
ERR_404 = {'Error': 'Not found'}, 404
ERR_409 = {'Error': 'Enrollment data is invalid'}, 409
PHOTO_BUCKET = ''

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
    },
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


def authenticate_user(user_id: int, sub: int) -> bool:
    """
    Authenticates user.
    Receives a user id and a JWT sub.
    Checks if requesting user is authorized for their request.
    Returns True if so, and False otherwise.
    """
    user = client.get(key=client.key(USERS, user_id))
    if not user:
        return False
    if user['sub'] != sub:
        return False
    return True


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
    token = r.json()['id_token']
    return {"token": token}, 200


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
        # Check user authorization
        query = client.query(kind=USERS)
        query.add_filter(filter=datastore.query.PropertyFilter("sub", "=", payload['sub']))
        results = query.fetch()
        if results["role"] != 'admin':
            return ERR_403
        # User has valid access, query users
        query = client.query(kind=USERS)
        results = list(query.fetch())
        return results, 200
    except:
        return {'Error': 'Unable to GET users'}, 500
    

@app.route('/' + USERS + '/<int:user_id>', methods=['GET'])
def get_user_by_id(user_id: int):
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
        query = client.query(kind=USERS)
        query.add_filter(datastore.query.PropertyFilter("sub", "=", payload['sub']))
        results = query.fetch()
        if results['role'] != 'admin' or results['sub'] != payload['sub']:
            return ERR_403
        # User is authorized, query for user
        if results['sub'] == payload['sub']:
            return results, 200
        query = client.query(kind=USERS)
        query.add_filter(datastore.query.PropertyFilter("id", "=", user_id))
        results = query.fetch()
        # Process accordingly
        user = {
            'courses': [],
            'role': '',
            'id': '',
            'sub': ''
        }
        if results['role'] == 'instructor' or results['roles'] == 'student':
            for course in results['courses']:
                user['courses'].append(f'{request.url_root}courses/{course}')
        user['id'] = results['id']
        user['role'] = results['role']
        user['sub'] = results['sub']
        if results['avatar'] is not None:
            id = str(results['id'])
            user['avatar'] = f'{request.url_root}users/{id}/avatar'
        return results, 200
    except:
        return {'Error': f'Unable to fetch user {user_id}'}, 500


@app.route('/' + USERS + '<int:user_id>' + '/' + AVATAR, methods=['POST', 'GET', 'DELETE'])
def user_avatar(user_id: int):
    """
    If method == POST:
        Creates or Updates user's avatar.
        Requires a POST request with the user's ID in the URL params.
        Requires a POST request with the new avatar in the body.
        Requires a valid JWT as a bearer token in the auth header that belongs to the user.
        Returns a JSON object with the URL for the new avatar if successful.
        Returns an appropriate error if not.
    If method == GET:
        Gets the avatar for the specified user.
        Requires a GET request with the user's ID in the URL params.
        Requires a valid JWT as a bearer token in the auth header that belongs to the user.
        Returns the file in the body if successful.
        Raises an appropriate error otherwise.
    If method == DELETE:
        Delete's the user's avatar, if it exists.
        Requires a DELETE request with the user's ID in the URL params.
        Requires a valid JWT as a bearer token in the auth header belonging to the user.
        Returns nothing with status code 204 if successful.
        Raises appropriate error otherwise.
    """
    if request.method == 'POST':
        # Validate content
        if 'file' not in request.files:
            return ERR_400
        # Validate JWT
        payload = verify_jwt(request)
        if type(payload) is AuthError:
            return ERR_401
        # Check user authorization
        if authenticate_user(user_id, payload['sub']) is False:
            return ERR_403
        # POST new avatar
        content = request.files['file']
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        content.filename = str(user_id)
        blob = bucket.blob(content.filename)
        content.seek(0)
        blob.upload_from_file(content)
        avatar_url = f'{request.url_root}/users/'
        avatar_url += content.filename
        avatar_url += "/avatar"
        return {"avatar_url": avatar_url}, 200
    elif request.method == 'GET':
        # Validate JWT
        payload = verify_jwt(request)
        if type(payload) is AuthError:
            return ERR_401
        # Authenticate user
        if authenticate_user(user_id, payload['sub']) is False:
            return ERR_403
        # Get file
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        blob = bucket.blob(user_id)
        avatar = io.BytesIO()
        blob.download_to_file(avatar)
        avatar.seek(0)
        if avatar is None:
            return ERR_404
        return send_file(avatar, mimetype='image/x-png', download_name=str(user_id)), 200
    elif request.method == 'DELETE':
        # Validate JWT
        payload = verify_jwt(request)
        if type(payload) is AuthError:
            return ERR_401
        # Authenticate user
        if authenticate_user(user_id, payload['sub']) is False:
            return ERR_403
        # Delete the file
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        blob = bucket.blob(user_id)
        avatar = io.BytesIO()
        blob.download_to_file(avatar)
        avatar.seek(0)
        if avatar is None:
            return ERR_404
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        blob = bucket.blob(user_id)
        blob.delete()
        return '', 204
    else:
        return ERR_403


@app.route('/' + COURSES, methods=['POST'])
def create_course():
    """
    Creates a new course in datastore.
    Requires a valid JWT as the bearer token in the auth header.
    Requires user to have admin access.
    Requires a valid instructor ID in the request body.
    Returns a JSON representing the new course if successful.
    Raises appropriate errors otherwise.
    """
    # Validate JWT
    payload = verify_jwt(request)
    if type(payload) is AuthError:
        return ERR_401
    # Check user authorization
    query = client.query(kind=USERS)
    query.add_filter(datastore.query.PropertyFilter("sub", "=", payload['sub']))
    results = query.fetch()
    if results['role'] != 'admin' or results['sub'] != payload['sub']:
        return ERR_403
    # Verify request params
    content = request.get_json()
    if "subject" not in content:
        return ERR_400
    elif "number" not in content:
        return ERR_400
    elif "title" not in content:
        return ERR_400
    elif "term" not in content:
        return ERR_400
    elif "instructor_id" not in content:
        return ERR_400
    # Verify that instructor exists
    instructor = client.get(key=client.key(USERS, int(content['instructor_id'])))
    if instructor is None:
        return ERR_400
    # Create new course
    new_course = datastore.Entity(key=client.key(USERS))
    new_course.update({
        "subject": content["subject"],
        "number": content["number"],
        "title": content["title"],
        "term": content["term"],
        "instructor_id": int(content["instructor_id"])
    })
    client.put(new_course)
    content["id"] = new_course.key.id
    content["self"] = request.url_root + COURSES + '/' + str(content["id"])
    return content, 201


@app.route('/' + COURSES, defaults={'offset': 0, 'limit': 3}, methods=['GET'])
@app.route('/' + COURSES + '/offset=<int:offset>&limit=<int:limit>')
def get_all_courses(offset: int, limit: int):
    """
    Lists all courses ordered by subject (non-deterministic within subject).
    Receives optional params of offset and limit.
    Paginates results based on offset and limit, with a default of 3 per query.
    Returns the # of courses specified with limit, starting with the course specified by offset.
    """
    query = client.query(kind=COURSES)
    query.projection = [
        "id",
        "instructor_id",
        "number",
        "subject",
        "term",
        "title"
    ]
    query.order = ["subject"]
    courses = list(query.fetch(offset=offset, limit=limit))
    for course in courses:
        course['self'] = request.url_root + COURSES + '/' + str(course['id'])
    next = request.url_root + COURSES + f'?limit={limit}&offset={offset + limit}'
    return {"courses": courses, "next": next}, 200


@app.route('/' + COURSES + '/<int:course_id>', methods=['GET', 'PATCH', 'DELETE'])
def get_course_by_id(course_id: int):
    """
    If method == GET:
        Fetches a single course by ID.
        Requires a valid courseID specified in URL params.
        Returns the course if it exists, or an error if not.
    If method == PATCH:
        Performs a partial update on the course specified in the URL params.
        Note: Endpoint cannot modify student enrollment.
        Requires a JWT as bearer token in Auth header.
        Requires admin role from user corresponding to the JWT.
        Returns the course with the updated values if successful.
        Raises appropriate errors if not.
    If method == DELETE:
        Deletes the course specified in the URL params.
        Removes the course from each student enrolled in it.
        Disassociates the instructor from the course.
        Requires a JWT as a bearer token in Auth header.
        Requires admin role from user corresponding to JWT.
    """
    if request.method == 'GET':
        query = client.query(kind=COURSES)
        query.projection = [
            "id",
            "instructor_id",
            "number",
            "subject",
            "term",
            "title"
        ]
        course = query.fetch()
        if course is None:
            return ERR_404
        course['self'] = request.url_root + COURSES + '/' + str(course['id'])
        return course, 200
    elif request.method == 'PATCH':
        # Validate JWT
        payload = verify_jwt(request)
        if type(payload) is AuthError:
            return ERR_401
        # Check user authorization
        user_query = client.query(kind=USERS)
        user_query.add_filter(filter=datastore.query.PropertyFilter("sub", "=", payload["sub"]))
        results = user_query.fetch()
        if results is None or results["role"] != "admin":
            return ERR_403
        # Check if course exists
        course = client.get(key=client.key(COURSES, course_id))
        if course is None:
            return ERR_403
        content = request.get_json()
        # Verify instructor is valid, if specified
        if 'instructor_id' in content:
            instructor = client.get(key=client.key(USERS, content['instructor_id']))
            if instructor is None:
                return ERR_400
        # Update specified params
        for param in content:
            course[param] = content['param']
        client.put(course)
        course['self'] = request.url_root + COURSES + '/' + course['id']
        return course, 200
    elif request.method == 'DELETE':
        # Validate JWT
        payload = verify_jwt(request)
        if type(payload) is AuthError:
            return ERR_401
        # Check user authorization
        query = client.query(kind=USERS)
        query.add_filter(datastore.query.PropertyFilter("sub", "=", payload['sub']))
        results = query.fetch()
        if results['role'] != 'admin':
            return ERR_403
        # Verify that course exists
        course = client.get(client.key(COURSES, course_id))
        if course is None:
            return ERR_403
        # Remove course from each enrolled student
        for student in course['students']:
            student_record = client.get(client.key(USERS, student))
            student_record['courses'].remove(course_id)
            client.put(student_record)
        # Delete the course
        client.delete(client.key(COURSES), course_id)
        return '', 204
    else:
        return ERR_404


@app.route('/' + COURSES + '/<int:course_id>' + '/' + STUDENTS, methods=['PATCH'])
def update_course_enrollment(course_id: int):
    """
    Update enrollment (enroll, disenroll) students from a course
    Requires a valid JWT as bearer token in auth header.
    Requires user to have admin access, or to be an instructor for the course.
    Receives an array in the body containing students to enroll and an array containing students to disenroll.
    Either array may be empty.
    Updates student enrollment accordingly.
    Returns nothing if successful, or raises an error appropriately.
    """
    # Verify JWT
    payload = verify_jwt(request)
    if type(payload) is AuthError:
        return ERR_401
    # Verify user authorization
    query = client.query(kind=USERS)
    query.add_filter(filter=datastore.query.PropertyFilter("sub", "=", payload['sub']))
    results = query.fetch()
    if results is None:
        return ERR_403
    elif results["role"] != 'admin' and results["role"] != 'instructor':
        return ERR_403
    # Check if instructor is authorized
    course = client.get(client.key(COURSES, course_id))
    if results['role'] == 'instructor' and results['sub'] != payload['sub']:
        return ERR_403
    # Enroll students, if any
    content = request.get_json()
    put_students = []
    for student in content['add']:
        if student in content['remove']:
            return ERR_409
        # Add course to student
        db_student = client.get(client.key(USERS, student))
        if db_student is None or db_student['role'] != 'student':
            return ERR_409
        if course_id not in db_student['courses']:
            db_student['courses'].append(course_id)
            put_students.append(db_student)
            # Add student to course
            course['students'].append(student)
    # Disenroll students, if any
    for student in content['remove']:
        # Remove course from student
        db_student = client.get(client.key(USERS, student))
        if db_student is None:
            return ERR_409
        if course_id in db_student['courses']:
            db_student['courses'].remove(course_id)
            put_students.append(db_student)
            # Remove student from course
            course['students'].remove(student)
    return '', 200


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=PORT, debug=True)
