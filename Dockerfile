FROM python:3.12.8-slim

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./

RUN mkdir /state

CMD [ "python", "./app.py" ]