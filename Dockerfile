FROM python:3.12.4-slim

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY shim.py ./

RUN mkdir /state

CMD [ "python", "./shim.py" ]