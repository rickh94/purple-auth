FROM python:3.9

RUN python3 -m pip install poetry
ADD ./pyproject.toml .
ADD ./poetry.lock .
RUN poetry install --no-dev --no-root

ADD ./app /app/app
COPY ./manage.py /app
WORKDIR /app
CMD poetry run uvicorn --proxy-headers --uds /socks/auth-service.sock --log-level debug app.main:app
