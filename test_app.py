import tempfile
from pathlib import Path

import pytest

from app import create_app


@pytest.fixture
def client():
    database = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    database.close()
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-key",
        "DATABASE": database.name,
    })

    with app.test_client() as test_client:
        yield test_client

    Path(database.name).unlink(missing_ok=True)


def register(client, username="testuser", password="hemligt123"):
    client.get("/")
    response = client.post("/register", data={
        "username": username,
        "password": password,
        "csrf_token": get_csrf_token(client),
    })
    assert response.status_code == 302


def get_csrf_token(client):
    with client.session_transaction() as session:
        return session["csrf_token"]


def test_registration_login_and_post(client):
    register(client)

    response = client.post("/post", data={
        "message": "Mitt första inlägg",
        "csrf_token": get_csrf_token(client),
    })

    assert response.status_code == 302
    assert "Mitt första inlägg" in client.get("/").get_data(as_text=True)


def test_user_cannot_delete_another_users_post(client):
    register(client, "person1")
    client.post("/post", data={
        "message": "Hemligt inlägg",
        "csrf_token": get_csrf_token(client),
    })

    client.post("/logout", data={"csrf_token": get_csrf_token(client)})
    register(client, "person2")
    response = client.post("/post/1/delete", data={
        "csrf_token": get_csrf_token(client),
    })

    assert response.status_code == 404
