import os

REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = os.getenv("REDIS_PORT")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
OTP_LENGTH = int(os.getenv("OTP_LENGTH", "8"))
OTP_LIFETIME = int(os.getenv("OTP_LIFETIME", "5"))
MAILGUN_KEY = os.getenv("MAILGUN_KEY")
MAILGUN_ENDPOINT = os.getenv("MAILGUN_ENDPOINT")
FROM_NAME = os.getenv("FROM_NAME") or "Authentication Code"
FROM_ADDRESS = os.getenv("FROM_ADDRESS")
VERSION = os.getenv("APP_VERSION")
DB_USERNAME = os.getenv("DB_USERNAME", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "root")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "27017")
DB_NAME = os.getenv("DB_NAME", "app")
