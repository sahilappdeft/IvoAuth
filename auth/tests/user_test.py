import pytest
from fastapi.testclient import TestClient
from main import app

@pytest.fixture
def client():
    return TestClient(app)

def test_signup(client):
    # Define test data
    register_data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "password": "securepassword"
    }

    # Make POST request to /signup endpoint
    response = client.post("/signup", json=register_data)

    # Assert response status code is 200
    assert response.status_code == 200

    # Assert response contains the user data
    assert "id" in response.json()
    assert response.json()["email"] == register_data["email"]

    # Clean up (delete the user created during the test)
    # Implement your cleanup logic here

# Write similar test cases for other endpoints such as /login, /verify-email, etc.
