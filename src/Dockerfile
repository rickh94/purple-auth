ARG ARCH=
FROM ${ARCH}python:3.9

RUN pip install pipenv
ADD ./Pipfile .
ADD ./Pipfile.lock .
RUN pipenv install --system --deploy

ADD ./app /app/app
COPY ./manage.py /app
WORKDIR /app
CMD uvicorn --host '0.0.0.0' --port 80 --log-level debug app.main:app