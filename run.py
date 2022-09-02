from http import client
from flask import Flask
from time import time
from flask import url_for, session, redirect, render_template
from authlib.integrations.flask_client import OAuth
from urllib import parse
import os

os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1' #redirect to http not https 
#app定義
app = Flask(__name__)
app.secret_key = '!secret'
#keycloak関連を定義
BASE_URL = 'http://localhost:3003'

KEYCLOAK_HOST = os.environ['KEYCLOAK_HOST']
KEYCLOAK_RELM_ID = os.environ['KEYCLOAK_RELM_ID']
CLIENT_ID = os.environ['CLIENT_ID']
CLIENT_SECRET = os.environ['CLIENT_SECRET']
API_BASE_URL = f'http://{KEYCLOAK_HOST}/realms/{KEYCLOAK_RELM_ID}/protocol/openid-connect'
ACCESS_TOKEN_URL = f'{API_BASE_URL}/token'
AUTHORIZE_RUL = f'{API_BASE_URL}/auth'
JWT_URI = f'{API_BASE_URL}/certs'

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

@app.route('/')
def index():
    token = dict(session).get('token', None)
    #既存のToken情報でユーザ情報取得できるかご確認する。
    if token:
        resp = oauth.keycloak.get('userinfo', token=token)
        # HTTP 401 Unauthorized ではなく場合、ログイン後の画面を出力(あくまでサンプルなので、ここで確認する必要があります)
        if resp.status_code != 401:
            user = resp.json()
            if (token['expires_at'] - time()) <= 0:
                from authlib.integrations.requests_client import OAuth2Session
                client = OAuth2Session(CLIENT_ID, CLIENT_SECRET, token=token)
                token = client.refresh_token(ACCESS_TOKEN_URL, token['refresh_token'])
                session['token'] = token
            return render_template("home.html", user=user, token=token)
        else: 
            return render_template("login.html")
    else:
        return render_template("login.html")


@app.route('/login')
def login():
    client = oauth.create_client('keycloak')
    redirect_uri = url_for('auth', _external=True)

    return client.authorize_redirect(redirect_uri)

@app.route('/auth')
def auth():
    token = oauth.keycloak.authorize_access_token()
    session['token'] = token

    return redirect('/')

@app.route('/logout')
def logout():
    
    token = session.get('token', None)
    id_token_hint = token['id_token']
    session.pop('token', None)

    #redirect先で/と別のとこに遷移したい場合、以下のように設定を追加
    #&post_logout_redirect_uri='+parse.quote('リダイレクト先URL')
    url = f'{API_BASE_URL}/logout' + \
        f'?id_token_hint={id_token_hint}&post_logout_redirect_uri=' + \
        parse.quote(BASE_URL)

    return redirect(url)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3003, debug=True)