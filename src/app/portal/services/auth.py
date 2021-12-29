from typing import Optional
from urllib.parse import quote_plus

import purple_auth_client as pac
from fastapi import HTTPException
from starlette import status
from starlette.responses import Response, RedirectResponse

from app.portal.security import auth_client, oauth2_scheme


def make_authenticated_response(
    url: str,
    id_token: str,
    refresh_token: Optional[str] = None,
    stay_logged_in: bool = False,
) -> Response:
    response = RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        oauth2_scheme.token_name,
        id_token,
        max_age=30 * 60,
        httponly=True,
        samesite="strict",
        secure=True,
    )
    if refresh_token:
        refresh_max_age = 30 * 24 * 60 * 60 if stay_logged_in else 35 * 60
        response.set_cookie(
            oauth2_scheme.refresh_token_name,
            refresh_token,
            max_age=refresh_max_age,
            httponly=True,
            samesite="strict",
            secure=True,
        )
    return response


async def handle_logout(id_token: str, refresh_token: str) -> None:
    try:
        await auth_client.delete_refresh_token(id_token, refresh_token)
    except (pac.AuthenticationFailure, pac.ValidationError):
        pass
    except pac.AuthClientError as e:
        raise HTTPException(status_code=500, detail=str(e))


async def handle_logout_everywhere(id_token: str) -> None:
    try:
        await auth_client.delete_all_refresh_tokens(id_token)
    except (pac.AuthenticationFailure, pac.ValidationError):
        pass
    except pac.AuthClientError as e:
        raise HTTPException(status_code=500, detail=str(e))


def make_logged_out_response(message: str) -> Response:
    response = RedirectResponse(
        f"/?message={quote_plus(message)}", status_code=status.HTTP_303_SEE_OTHER
    )
    response.delete_cookie(oauth2_scheme.token_name)
    response.delete_cookie(oauth2_scheme.refresh_token_name)
    return response
