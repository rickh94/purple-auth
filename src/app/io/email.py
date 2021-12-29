import aiohttp

from app import config


class EmailError(Exception):
    pass


async def send(to: str, subject: str, text: str, from_name: str, reply_to: str = None):
    send_data = {
        "from": f"{from_name} <{config.FROM_ADDRESS}>",
        "to": to,
        "subject": subject,
        "text": text,
    }
    if reply_to:
        send_data["h:Reply-To"] = reply_to
    async with aiohttp.ClientSession() as session:
        res = await session.post(
            config.MAILGUN_ENDPOINT,
            auth=aiohttp.BasicAuth("api", config.MAILGUN_KEY),
            data=send_data,
        )
        if res.status != 200:
            raise EmailError(f"Something went wrong: {await res.text()}")
