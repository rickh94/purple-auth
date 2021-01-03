from odmantic import Model, Field
from pydantic import Json


class App(Model):
    name: str = Field(..., title="Name of the app")
    app_id: str = Field(..., title="app unique id")
    key: Json
