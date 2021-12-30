from typing import Optional

import mongox
from fastapi import HTTPException

from app.portal.models.user_model import User


async def get_user_by_email(email: str) -> Optional[User]:
    try:
        return await User.query(User.email == email).get()
    except mongox.NoMatchFound:
        return None
    except mongox.MultipleMatchesFound:
        raise HTTPException(
            status_code=500, detail="Multiple users found with the same email"
        )


async def create_user_from_email(email: str) -> User:
    return await User(email=email).insert()


async def check_or_create_user_from_email(email: str) -> User:
    user = await get_user_by_email(email)
    if not user:
        user = await create_user_from_email(email)
    return user


async def delete_user(user: User) -> None:
    await user.delete()
