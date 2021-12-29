def test_index_renders(test_client):
    response = test_client.get("/")

    assert response.status_code == 200
    # assert "Authentication without passwords" in response.text
