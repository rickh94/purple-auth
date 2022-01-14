from typing import Optional

import mongox
from fastapi import HTTPException

from app.portal.crud import clientapp_crud
from app.portal.models.user_model import User
from app.portal.services import deletion_protection


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
    if user.deletion_protection:
        raise HTTPException(
            status_code=400,
            detail="You need to turn off deletion protection to delete your account.",
        )
    await clientapp_crud.delete_user_apps(user)
    await user.delete()


async def update_user(user: User, name: str) -> User:
    user.name = name
    await user.save()
    return user


async def disable_deletion_protection(user: User, dp_code: str) -> User:
    """
    Disable deletion protection for a user account.

    :param user:  the user to disable deletion protection for
    :param code:  the one time use code emailed to the user
    :return:      the user object
    """
    if not deletion_protection.verify_dp_code(user, "account", dp_code):
        raise HTTPException(status_code=400, detail="Invalid deletion protection code.")
    user.deletion_protection = False
    await user.save()
    return user
