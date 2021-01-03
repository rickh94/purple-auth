import pytest
from aioresponses import aioresponses

from app import config
from app.io import email as io_email


@pytest.fixture
def mock_aioresponse():
    with aioresponses() as m:
        yield m


@pytest.mark.asyncio
async def test_send_success(mock_aioresponse):
    mock_aioresponse.post(config.MAILGUN_ENDPOINT, status=200)
    await io_email.send(
        to="test@example.com",
        subject="Test Subject",
        text="Test text",
        from_name="Test Sender",
    )

    request = list(mock_aioresponse.requests.values())[0][0]
    assert request.kwargs["data"]["from"] == "Test Sender <test@mg.example.com>"
    assert request.kwargs["data"]["to"] == "test@example.com"
    assert request.kwargs["data"]["text"] == "Test text"
    assert request.kwargs["data"]["subject"] == "Test Subject"
    assert request.kwargs["auth"].login == "api"
    assert request.kwargs["auth"].password == config.MAILGUN_KEY


@pytest.mark.asyncio
async def test_send_failure(mock_aioresponse):
    mock_aioresponse.post(config.MAILGUN_ENDPOINT, status=400, body="Bad Request")
    with pytest.raises(io_email.EmailError) as error_info:
        await io_email.send(
            to="test@example.com",
            subject="Test Subject",
            text="Test text",
            from_name="Test Sender",
        )
    assert str(error_info.value) == "Something went wrong: Bad Request"
