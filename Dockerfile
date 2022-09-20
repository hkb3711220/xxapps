FROM python:3.9.12
WORKDIR /app
COPY . ./
# Keycloakの証明書をpythonライブライに入れること
RUN pip install -r requirements.txt && cat /app/server.crt >> /usr/local/lib/python3.9/site-packages/certifi/cacert.pem 
EXPOSE 3000
CMD ["python", "run.py"]
