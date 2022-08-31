from flask import Flask
from flask import url_for, session, redirect, render_template
from authlib.integrations.flask_client import OAuth
from urllib import parse
import logging
import os

os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1' #redirect to http not https 

logger = logging.getLogger(__name__)
#app定義
app = Flask(__name__)
app.secret_key = '!secret'
#keycloak関連を定義
keycloak_host = "172.18.0.2:8080" #環境変数
keycloak_relm_id = 'demo' #環境変数
client_id = 'xxapps'
client_secret='wW6Uryh9rLviHRzzv68PH032TySSnZXo'
scope='openid email profile',
access_token_url=f'http://{keycloak_host}/realms/{keycloak_relm_id}/protocol/openid-connect/token'
authorize_url=f'http://{keycloak_host}/realms/{keycloak_relm_id}/protocol/openid-connect/auth'
oauth = OAuth(app)
oauth.register(
    name="keycloak", 
    client_id=client_id, #環境変数
    client_secret=client_secret, #環境変数
    api_base_url= f'http://{keycloak_host}/realms/{keycloak_relm_id}/protocol/openid-connect/',
    request_token_url=None,
    jwks_uri=f'http://{keycloak_host}/realms/{keycloak_relm_id}/protocol/openid-connect/certs', #id_token取得するため
    access_token_url=access_token_url,
    authorize_url=authorize_url,
    client_kwargs={
        'scope': 'openid email profile',
    }
)


@app.route('/')
def index():
    user = dict(session).get('user', None)
    token = dict(session).get('token', None)
    
    if user and token:
        #ログインプロセス
        from authlib.integrations.requests_client import OAuth2Session
        scope = token["scope"]
        oauth_session = OAuth2Session(
            client_id, 
            client_secret, 
            authorization_endpoint=authorize_url, 
            token_endpoint=access_token_url,
            scope=scope, 
            token=token)
            
        try:
            token = oauth_session.refresh_token(
                access_token_url, 
                refresh_token=token['refresh_token']
                )
            return render_template("home.html", user=user, token=token)
        except:
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
    resp = oauth.keycloak.get('userinfo', token=token) #'http://{keycloak_host}/realms/{keycloak_relm_id}/protocol/openid-connect/userinfo',
    resp.raise_for_status()
    profile = resp.json()
    session['token'] = token
    session['user'] = profile

    return redirect('/')

@app.route('/logout')
def logout():
    
    token = session.get('token', None)
    id_token_hint = token['id_token']
    session.pop('user', None)
    session.pop('token', None)
    #redirect先で/と別のとこに遷移したい場合、以下のように設定を追加
    #&post_logout_redirect_uri='+parse.quote('リダイレクト先URL')
    url = f'http://{keycloak_host}/realms/{keycloak_relm_id}/protocol/openid-connect/logout?id_token_hint={id_token_hint}&post_logout_redirect_uri='+parse.quote('http://localhost:3003')

    return redirect(url)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3003, debug=True)