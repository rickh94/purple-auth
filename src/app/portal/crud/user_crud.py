from typing import Optional

from app.dependencies import engine
from app.portal.models.user_model import User


async def get_user_by_email(email: str) -> Optional[User]:
    user = await engine.find_one(User, User.email == email)
    return user


async def create_user_from_email(email: str) -> User:
    user = User(email=email)
    await engine.save(user)
    return user


async def check_or_create_user_from_email(email: str) -> User:
    user = await get_user_by_email(email)
    if not user:
        user = await create_user_from_email(email)
    return user


async def delete_user(user: User) -> None:
    await engine.delete(user)
