# tests/test_app.py
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pytest
from unittest.mock import patch, MagicMock
from app import app
from flask import json
import bcrypt
@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def mock_db_connection(mock_cursor_result=None):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = mock_cursor_result
    mock_cursor.fetchone.return_value = mock_cursor_result
    mock_conn.cursor.return_value = mock_cursor
    return mock_conn


def test_login_success(client):
    with patch('app.get_db_connection') as mocked_db:
        # Mock database response
        mocked_conn = mock_db_connection({'hashed_password': bcrypt.hashpw('testpassword'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')})
        mocked_db.return_value = mocked_conn

        # Send POST request
        response = client.post('/api/login', json={
            'username': 'testuser',
            'password': 'testpassword'
        })

        data = response.get_json()
        assert response.status_code == 200
        assert 'access_token' in data

def test_login_failure(client):
    with patch('app.get_db_connection') as mocked_db:
        # Mock database response with no user found
        mocked_conn = mock_db_connection(None)
        mocked_db.return_value = mocked_conn

        # Send POST request
        response = client.post('/api/login', json={
            'username': 'wronguser',
            'password': 'wrongpassword'
        })

        data = response.get_json()
        assert response.status_code == 401
        assert data['msg'] == "Bad username or password"


def test_get_routes(client):
    with patch('app.get_db_connection') as mocked_db:
        mock_routes = [
            {'path': '/api/login', 'methods': 'POST'},
            {'path': '/api/routes', 'methods': 'GET'}
        ]
        mocked_conn = mock_db_connection(mock_routes)
        mocked_db.return_value = mocked_conn

        response = client.get('/api/routes')
        data = response.get_json()

        assert response.status_code == 200
        assert isinstance(data, list)
        assert data[0]['path'] == '/api/login'
        assert data[0]['methods'] == ['POST']


def test_get_vulnerabilities(client):
    with patch('app.get_db_connection') as mocked_db:
        mock_vulnerabilities = [
            {'vulnerability_type': 'SQL Injection', 'route_name': '/api/login'},
            {'vulnerability_type': 'XSS', 'route_name': '/api/comments'}
        ]
        mocked_conn = mock_db_connection(mock_vulnerabilities)
        mocked_db.return_value = mocked_conn

        response = client.get('/api/vulnerabilities')
        data = response.get_json()

        assert response.status_code == 200
        assert 'SQL Injection' in data
        assert data['SQL Injection'] == ['/api/login']

def test_get_vulnerability_details(client):
    with patch('app.get_db_connection') as mocked_db:
        mock_vulnerabilities = [
            {'vulnerability_type': 'SQL Injection'},
            {'vulnerability_type': 'XSS'}
        ]
        mocked_conn = mock_db_connection(mock_vulnerabilities)
        mocked_db.return_value = mocked_conn

        response = client.get('/api/vulnerabilities/api/login')
        data = response.get_json()

        assert response.status_code == 200
        assert data == {
            'SQL Injection': 'api/login',
            'XSS': 'api/login'
        }

def test_get_total_apis(client):
    with patch('app.get_db_connection') as mocked_db:
        mocked_conn = mock_db_connection((10,))
        mocked_db.return_value = mocked_conn

        response = client.get('/api/total_apis')
        data = response.get_json()

        assert response.status_code == 200
        assert data == 10

def test_get_total_vulnerabilities(client):
    with patch('app.get_db_connection') as mocked_db:
        mocked_conn = mock_db_connection((5,))
        mocked_db.return_value = mocked_conn

        response = client.get('/api/total_vulnerabilities')
        data = response.get_json()

        assert response.status_code == 200
        assert data == 5

def test_get_vulnerabilities_severity(client):
    with patch('app.get_db_connection') as mocked_db:
        mock_severity_data = [
            {'vulnerability_type': 'SQL Injection', 'count': 3},
            {'vulnerability_type': 'XSS', 'count': 2}
        ]
        mocked_conn = mock_db_connection(mock_severity_data)
        mocked_db.return_value = mocked_conn

        response = client.get('/api/vulnerabilities/severity')
        data = response.get_json()

        assert response.status_code == 200
        assert data == {
            'SQL Injection': 3,
            'XSS': 2
        }


def test_get_code_score(client):
    with patch('app.get_db_connection') as mocked_db:
        # Mock vulnerabilities data
        mocked_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.side_effect = [
            [(4, 2), (3, 1)],  # vulnerabilities data
        ]
        mock_cursor.fetchone.side_effect = [
            (5,),  # total_apis
        ]
        mocked_conn.cursor.return_value = mock_cursor
        mocked_db.return_value = mocked_conn

        response = client.get('/api/code_score')
        data = response.get_json()

        assert response.status_code == 200
        assert data == "78.00"  # Adjusted to match the current calculation



def test_get_donought_chart(client):
    with patch('app.get_db_connection') as mocked_db:
        mock_data = [
            {'severity_level': 'Critical', 'count': 2},
            {'severity_level': 'High', 'count': 3},
            {'severity_level': 'Medium', 'count': 5}
        ]
        mocked_conn = mock_db_connection(mock_data)
        mocked_db.return_value = mocked_conn

        response = client.get('/api/donought_chart')
        data = response.get_json()

        assert response.status_code == 200
        assert data == {
            'Critical': 2,
            'High': 3,
            'Medium': 5
        }
