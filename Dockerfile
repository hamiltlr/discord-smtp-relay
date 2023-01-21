FROM python:3.7.16-slim

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app .

CMD [ "python", "./discord_relay.py" ]
