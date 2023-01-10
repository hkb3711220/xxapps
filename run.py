from flask import Flask
from time import time
from flask import url_for, session, redirect, render_template
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.flask_client import OAuth
import os
import logging

logger = logging.getLogger(__name__)

class LoginUser(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

#環境変数
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1' 
#keycloak関連を定義
BASE_URL = os.environ['BASE_URL']
BASE_DIR = os.path.dirname(__file__)
KEYCLOAK_HOST = os.environ['KEYCLOAK_HOST']
KEYCLOAK_RELM_ID = os.environ['KEYCLOAK_RELM_ID']
CLIENT_ID = os.environ['CLIENT_ID']
CLIENT_SECRET = os.environ['CLIENT_SECRET']
API_BASE_URL = f'http://{KEYCLOAK_HOST}/realms/{KEYCLOAK_RELM_ID}/protocol/openid-connect'
ACCESS_TOKEN_URL = f'{API_BASE_URL}/token'
AUTHORIZE_RUL = f'{API_BASE_URL}/auth'
JWT_URI = f'{API_BASE_URL}/certs'

#app定義
app = Flask(__name__)
app.secret_key = '!secret'
login_manager = LoginManager()
login_manager.init_app(app)
#Oauth clientの設定
oauth = OAuth(app)
oauth.register(
    name="keycloak", 
    client_id=CLIENT_ID, 
    client_secret=CLIENT_SECRET, 
    api_base_url=API_BASE_URL+'/',
    request_token_url=None,
    jwks_uri=JWT_URI, #id_token取得するため
    access_token_url=ACCESS_TOKEN_URL,
    authorize_url=AUTHORIZE_RUL,
    client_kwargs={
        'scope': 'openid email profile',
    }
)
client = OAuth2Session(
    CLIENT_ID,
    CLIENT_SECRET, 
    authorization_endpoint=AUTHORIZE_RUL,
    token_endpoint=ACCESS_TOKEN_URL,
)

@login_manager.user_loader
def load_user(user_id):
    return LoginUser(user_id)

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/xxapp')
@login_required
def xxapp():
    token = dict(session).get('token', None)
    userinfo = dict(session).get('user', None)

    if current_user.id == userinfo['sub']: 
        if token:
            if (token['expires_at'] - time()) <= 2:
                try:
                    token = client.refresh_token(
                        url=ACCESS_TOKEN_URL,
                        client_id=CLIENT_ID,
                        client_secret=CLIENT_SECRET,
                        refresh_token=token['refresh_token'])
                    session['token'] = token
                except Exception as e:
                    logout_user()
                    return render_template('login.html', message=str(e))
            return render_template("home.html", user=userinfo, token=token)

#login url
@app.route('/login')
def login():
    client = oauth.create_client('keycloak')
    redirect_uri = url_for('auth', _external=True)

    return client.authorize_redirect(redirect_uri)

#callback url
@app.route('/auth')
def auth():
    token = oauth.keycloak.authorize_access_token()
    session['token'] = token
    user = token['userinfo']
    session['user'] = user

    if user:
        current_login_user = LoginUser(user_id=user['sub'])
        login_user(current_login_user)


    return redirect('/xxapp')

#logout url
@app.route('/logout')
def logout():
    token = session.get('token', None)
    refresh_token = token['refresh_token']
    session.pop('token', None)
    session.pop('user', None)
    logout_user()
    #Revoke Endpointをコールし、Client Session()
    client.revoke_token(url=f'{API_BASE_URL}/revoke', token=refresh_token)

    return redirect('/')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3000, debug=True)