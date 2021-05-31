import base64
import json
from typing import Optional
import hmac
import hashlib

from fastapi import FastAPI, Form, Cookie, Body
from fastapi import responses
from fastapi.responses import Response


app = FastAPI()

SECRET_KEY = '9d1b827263c5b1902eb1f33c2c233c4ff820740793343425523d15e52d59f349'
PASSWORD_SALT = '2e3b91b0232a35092734dd76a5bec381303732a2765da3eacb410c3027b688f1'


def sign_data(data: str) -> str:
    """Returns signed data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]['password'].lower()
    return stored_password_hash == password_hash


users = {
    'alex@user.com': {
        'name': 'alex',
        'password': 'de5a67c888bc8421c6a3d01f3d01ff449c31674d03697cadab4a21737322d0f7',
        'balance': 100_000
    },
    'petr@user.com' : {
        'name': 'petr',
        'password': 'def9d92861ee06b539448f2cbb356a2e02a9d342cadd89b026471a843941c798',
        'balance': 555_555
    }
}


@app.get('/')
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type='text/html')
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    return Response(f'Hello, {users[valid_username]["name"]}!<br>Your balance: {users[valid_username]["balance"]}', 
    media_type='text/html')


@app.post('/login')
def process_login_page(data: dict = Body(...)):
    username = data['username']
    password = data['password']
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Idk u!"
            }), 
            media_type='application/json')

    response = Response(
        json.dumps({
                "success": True,
                "message": f"Hello, {user['name']}!<br>Your balance: {user['balance']}"
            }),
        media_type='application/json')
    
    username_signed = base64.b64encode(username.encode()).decode() + "." + sign_data(username)
    response.set_cookie(key='username', value=username_signed)
    return response
