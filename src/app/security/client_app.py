from jwcrypto import jwk

from app.io.models import ClientApp


def export_public_key(client_app: ClientApp) -> dict:
    key = jwk.JWK(**client_app.key)
    return key.export_public(as_dict=True)
