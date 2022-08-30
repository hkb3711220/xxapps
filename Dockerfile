FROM python:3.9.12
COPY requirements.txt ./
RUN pip install -r requirements.txt
WORKDIR /app
COPY . ./
RUN chmod 744 run.py
EXPOSE 3003
CMD ["python", "run.py"]
