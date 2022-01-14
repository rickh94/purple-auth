import ujson
from starlette.datastructures import MutableHeaders


def make_show_notification_header(
    headers: MutableHeaders, title: str, message: str, level: str = "info"
) -> str:
    notification_data = {
        "showNotification": {"title": title, "message": message, "level": level}
    }
    return make_event_header(headers, notification_data)


def make_event_header(headers: MutableHeaders, event_info: dict) -> str:
    next_header = {}
    if "HX-Trigger" in headers:
        next_header = ujson.loads(headers["HX-Trigger"])
    next_header.update(event_info)
    return ujson.dumps(next_header)
