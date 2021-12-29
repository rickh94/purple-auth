from passlib.context import CryptContext

PWD_CONTEXT = CryptContext(schemes=["argon2"], deprecated="auto", argon2__rounds=16)
