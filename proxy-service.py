from flask import Flask, request, jsonify
import requests
from functools import wraps
import jwt
import json

'''
The only difference between the proxy endpoints and the actual service endpoints is
that the service endpoints will have /api/v1 in the path as well
'''

app = Flask(__name__)


def load_config():
    with open('config.json') as config_file:
        config = json.load(config_file)
    return config


config = load_config()
jwtDecodedToken = {}
app.config['SECRET KEY'] = 'thisisasecretkey!@#$'
app.config['SERVICE KEY'] = 'thisisasecretkey!@#$'


def get_base_url(path):
    return config['api_base_url'][get_first_part(path)]


def get_first_part(string):
    parts = string[1:].split('/', 1)
    return parts[0]


def authenticate_request(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        global jwtDecodedToken
        header = request.headers.get('Authorization')
        token = ''
        if header is not None and header.startswith('Bearer '):
            token = header[7:]

        if not token:
            return jsonify({'message': 'Authentication is missing!'}), 401

        try:
            jwtDecodedToken = jwt.decode(token, app.config['SECRET KEY'], options={"verify_signature": False},
                                         algorithms=['HS256'])
            print(jwtDecodedToken)
            # Extract claims, expiry date and roles
        except Exception as e:
            return jsonify({'message': 'Authentication token is invalid!'}), 401

        return fn(*args, **kwargs)

    return wrapper


def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if jwtDecodedToken is None:
                return {'message': 'Insufficient permissions'}, 403
            user_roles = jwtDecodedToken.get('role') if jwtDecodedToken.get('role') is not None else []
            if 'super' in user_roles:
                return fn(*args, **kwargs)
            # Get the path parameter from the request
            path = request.path
            # Determine the required role based on the path
            if roles not in user_roles:
                return {'message': 'Insufficient permissions'}, 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def handle_api_request(path):
    headers = {
        'Secret-Key': app.config['SERVICE KEY'],
        'Authorization': request.headers.get('Authorization')
    }
    url = get_base_url(path) + path
    response = None

    if request.method == 'GET':
        response = requests.get(url, headers=headers)
    elif request.method == 'POST':
        json_request = request.json
        response = requests.post(url, json=json_request, headers=headers)

    if response is None:
        response = {
            'message': 'Not found'
        }, 404

    return response


@app.route('/authentication/authenticate', methods=['POST'])
def get_authentication():
    response = handle_api_request('/authentication/authenticate')
    if response.ok:
        # Decode the content into a string and parse as JSON
        content = response.content.decode('utf-8')
        json_data = json.loads(content)
        return jsonify(json_data)

    return jsonify({'message': 'Failed to retrieve data'})


@app.route('/financial/<path:path>', methods=['GET', 'POST'])
@authenticate_request
@role_required('finance')
def handle_financial_service_api_request(path):
    response = handle_api_request('/financial/' + path)
    return response.content, response.status_code, response.headers.items()


@app.route('/account/create/<path:path>', methods=['POST'])
def handle_account_create_api_request(path):
    response = handle_api_request('/account/create/' + path)
    if response.ok:
        # Decode the content into a string and parse as JSON
        content = response.content.decode('utf-8')
        json_data = json.loads(content)
        return jsonify(json_data)

    return jsonify({'message': 'Failed to retrieve data'})


@app.route('/account/<path:path>', methods=['GET', 'POST'])
@authenticate_request
@role_required('account')
def handle_account_service_api_request(path):
    response = handle_api_request('/account/' + path)
    if response.ok:
        # Decode the content into a string and parse as JSON
        content = response.content.decode('utf-8')
        json_data = json.loads(content)
        return jsonify(json_data)

    return jsonify({'message': 'Failed to retrieve data'})


if __name__ == '__main__':
    app.run(debug=True, port=5001)
