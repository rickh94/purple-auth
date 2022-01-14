from pathlib import Path

from starlette.templating import Jinja2Templates

template_dir = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(template_dir.absolute()))


def initials(words: str) -> str:
    return "".join([word[0] for word in words.split(" ")])


def icon_color(app_id: str) -> str:
    """
    Uses the uuid to create a hex color for the background of the initials
    in the list
    :param app_id: string version of the app uuid
    :return: hex color
    """
    if len(app_id) < 6:
        return "#000000"
    six_digits = app_id[:6]
    if not set(six_digits).issubset("0123456789abcdef"):
        return "#000000"
    return f"#{six_digits}"


templates.env.filters["initials"] = initials
templates.env.filters["icon_color"] = icon_color
