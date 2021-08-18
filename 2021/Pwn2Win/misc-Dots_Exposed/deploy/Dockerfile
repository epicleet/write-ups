FROM python:3

RUN pip3 install -v gunicorn

RUN pip3 install flask Flask-Limiter asciidots

ADD app /app

WORKDIR /app

RUN echo "CTF-BR{gosh,I_hate_those_fucking_0x0a}" > /flag

CMD gunicorn --bind 0.0.0.0:80 -w 5 app:app

EXPOSE 80


