from app.models.client_app_model import ClientApp


def export_public_key(client_app: ClientApp) -> dict:
    return client_app.get_key().export_public(as_dict=True)
