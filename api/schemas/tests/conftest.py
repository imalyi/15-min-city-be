from typing import AsyncGenerator, Generator

import pytest

from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport

import os

os.environ["ENV_STATE"] = "test"

from api.database import database  #  noqa: E402
from api.api import app  # noqa: E402


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture()
def client() -> Generator:
    yield TestClient(app)


@pytest.fixture(autouse=True)
async def db() -> AsyncGenerator:
    await database.connect()
    yield database
    await database.disconnect()


@pytest.fixture()
async def async_client(client):
    transport = ASGITransport(app=app)
    async with AsyncClient(base_url=client.base_url, transport=transport) as ac:
        yield ac
