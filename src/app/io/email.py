import aiohttp

from app import config


class EmailError(Exception):
    pass


async def send(to: str, subject: str, text: str):
    async with aiohttp.ClientSession() as session:
        res = await session.post(
            config.MAILGUN_ENDPOINT,
            auth=aiohttp.BasicAuth("api", config.MAILGUN_KEY),
            data={
                "from": f"{config.FROM_NAME} <{config.FROM_ADDRESS}>",
                "to": to,
                "subject": subject,
                "text": text,
            },
        )
        if res.status != 200:
            raise EmailError(f"Something went wrong: {await res.text()}")
