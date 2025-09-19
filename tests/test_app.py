from app import app
import pytest

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_index(client):
    """Test halaman utama ('/')"""
    rv = client.get('/')
    assert rv.status_code == 200
    assert b"Welcome" in rv.data or b"Bank" in rv.data
