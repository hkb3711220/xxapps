
# Simple Flask Apps,  authenticated via Keycloak

## Keycloak起動
------------------------------
```bash
docker run -d --name keycloak -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:19.0.1 start-dev
```
以下のリンクでKeycloakにアクセス可能 http://localhost:8080  



## RealmとClient作成、およびClientの設定
------------------------------
https://www.keycloak.org/docs/latest/server_admin/#proc-creating-a-realm_server_administration_guide

上記のリンクに沿って新しいRealmとClientを作成する
- Realm Name: 好きな名前
- Client Name: 好きな名前
  
Clientの管理画面にて、Client authenticationを有効化した上で、CredentailsタグからClient secretを取得する。
- Client Secret: 自動生成

テストのため、Clientの管理画面にて以下の設定を行う。
- Valid redirect URIs: http://localhost:3003/*
- Valid post logout redirect URIs: *
- Web origins: *



## Run Apps
------------------------------
必要なライブライを導入する
```bash
pip install -r requirements.txt
```

環境変数設定
```bash
export BASE_URL="http://localhost:3000"
export KEYCLOAK_HOST='localhost:8080'
export KEYCLOAK_RELM_ID='demo' #作ったRealmの名前
export CLIENT_ID='demo'　#作ったClientの名前
export CLIENT_SECRET='取得したSecretの値'
```
アプリ実行
```bash
python run.py
```

以下のリンクでAppにアクセス可能 http://localhost:3003
