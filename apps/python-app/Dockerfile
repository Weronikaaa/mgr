FROM python:3.8

WORKDIR /app
COPY . .

RUN apt-get update && apt-get install -y telnet ftp curl

RUN pip install -r requirements.txt

RUN chmod -R 777 /app

EXPOSE 5000

USER root

ENV FLASK_ENV=development
ENV DEBUG=true
ENV AWS_SECRET_ACCESS_KEY=test123fake
ENV API_TOKEN=hardcoded-token-in-image

CMD ["python", "app.py"]
