import pytest
import os
import tempfile
import json
from flask import Flask, request, jsonify
from wifis_web_tool import HTTPRequestTool

@pytest.fixture(scope="session")
def test_data_dir():
    # Create a temporary directory for test data
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield tmp_dir

@pytest.fixture(scope="session")
def common_files_path(test_data_dir):
    # Create a test common_files.txt
    test_files = [
        "robots.txt",
        "sitemap.xml",
        "admin.php",
        "login.php",
        "config.php"
    ]
    file_path = os.path.join(test_data_dir, "common_files.txt")
    with open(file_path, "w") as f:
        f.write("\n".join(test_files))
    return file_path

@pytest.fixture(scope="session")
def http_headers_path(test_data_dir):
    # Create a test http_headers.json
    test_headers = {
        "request_headers": {
            "User-Agent": "Test User Agent",
            "Accept": "text/html",
            "Host": "example.com"
        },
        "response_headers": {
            "Server": "Test Server",
            "Content-Type": "text/html",
            "X-Frame-Options": "DENY"
        }
    }
    file_path = os.path.join(test_data_dir, "http_headers.json")
    with open(file_path, "w") as f:
        json.dump(test_headers, f)
    return file_path

@pytest.fixture
def test_app():
    app = Flask(__name__)
    
    @app.route('/')
    def index():
        return "Test Server Response", 200
    
    @app.route('/robots.txt')
    def robots():
        return "User-agent: *\nDisallow: /admin/", 200
    
    @app.route('/sitemap.xml')
    def sitemap():
        return "<?xml version='1.0' encoding='UTF-8'?><urlset></urlset>", 200
    
    @app.route('/admin.php')
    def admin():
        return "Admin Panel", 200
    
    @app.route('/login.php')
    def login():
        return "Login Page", 200
    
    @app.route('/config.php')
    def config():
        return "Configuration File", 200
    
    return app

@pytest.fixture
def test_client(test_app):
    return test_app.test_client()

@pytest.fixture
def http_tool(test_client):
    # Monkey patch requests to use our test client
    def mock_request(method, url, **kwargs):
        # Convert requests kwargs to Flask test client kwargs
        headers = kwargs.get('headers', {})
        data = kwargs.get('data', None)
        
        # Extract path from URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path
        
        # Make request using test client
        response = test_client.open(
            path=path,
            method=method,
            headers=headers,
            data=data
        )
        
        # Convert Flask response to requests-like response
        class MockResponse:
            def __init__(self, flask_response):
                self.status_code = flask_response.status_code
                self.text = flask_response.get_data(as_text=True)
                self.content = flask_response.get_data()
                self.headers = dict(flask_response.headers)
                self.raw = type('obj', (object,), {'version': 11.0})
                self.reason = "OK"
        
        return MockResponse(response)
    
    # Create HTTPRequestTool instance
    tool = HTTPRequestTool()
    
    # Monkey patch the requests module
    import requests
    original_request = requests.request
    requests.request = mock_request
    
    yield tool
    
    # Restore original requests
    requests.request = original_request 