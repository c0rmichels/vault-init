FROM python:3.7.6-alpine3.11
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY vault-init.py ./
CMD [ "python", "./vault-init.py" ]
