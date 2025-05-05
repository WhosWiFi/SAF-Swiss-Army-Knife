import pytest
from unittest.mock import patch, MagicMock
from wifis_web_tool import HTTPRequestTool

@pytest.fixture
def http_tool():
    return HTTPRequestTool()

def test_process_request():
    # Create a simple mock response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "Test Response"
    mock_response.headers = {"Content-Type": "text/html"}
    mock_response.raw.version = 11.0
    mock_response.reason = "OK"

    # Mock requests.request to return our mock response
    with patch('requests.request', return_value=mock_response) as mock_request:
        tool = HTTPRequestTool()
        
        # Test basic request
        request_text = "GET / HTTP/1.1\nHost: test.com"
        result = tool.process_request(request_text)
        
        # Basic validation
        assert isinstance(result, dict)
        assert 'response' in result
        assert 'jwt_tokens' in result
        
        # Test error case
        request_text = ""
        result = tool.process_request(request_text)
        assert 'error' in result

def test_check_common_files():
    # Create a simple mock response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "Test File Content"
    mock_response.headers = {"Content-Type": "text/html"}
    mock_response.content = b"Test File Content"

    # Mock the file operations
    mock_common_files = ["/robots.txt", "/sitemap.xml", "/admin.php"]
    
    with patch('builtins.open', MagicMock()) as mock_open, \
         patch('requests.request', return_value=mock_response), \
         patch('json.load', return_value={'request_headers': {}, 'response_headers': {}}):
        
        # Configure the mock file to return our list of common files
        mock_file = MagicMock()
        mock_file.__enter__.return_value = mock_file
        mock_file.__exit__.return_value = None
        mock_file.readlines.return_value = [f"{file}\n" for file in mock_common_files]
        mock_open.return_value = mock_file
        
        tool = HTTPRequestTool()
        
        # Test basic request
        request_text = "GET / HTTP/1.1\nHost: test.com"
        result = tool.check_common_files(request_text)
        
        # Basic validation
        assert isinstance(result, dict)
        assert 'total_files' in result
        assert 'total_files_checked' in result
        assert 'files_found' in result
        assert 'found_files' in result
        assert 'checked_files' in result
        
        # Test error case
        request_text = ""
        result = tool.check_common_files(request_text)
        assert 'error' in result

def test_analyze_headers():
    # Create a simple mock response
    mock_response = MagicMock()
    mock_response.headers = {
        "Content-Type": "text/html",
        "Server": "TestServer"
    }
    mock_response.text = "Test Response"

    # Mock the file operations and requests
    with patch('builtins.open', MagicMock()) as mock_open, \
         patch('json.load', return_value={'request_headers': {}, 'response_headers': {}}), \
         patch('requests.request', return_value=mock_response):
        
        # Configure the mock file
        mock_file = MagicMock()
        mock_file.__enter__.return_value = mock_file
        mock_file.__exit__.return_value = None
        mock_open.return_value = mock_file
        
        tool = HTTPRequestTool()
        
        # Test basic request
        request_text = "GET / HTTP/1.1\nHost: test.com\nUser-Agent: test"
        result = tool.analyze_headers(request_text)
        
        # Basic validation
        assert isinstance(result, dict)
        assert 'total_headers' in result
        assert 'request_headers' in result
        assert 'response_headers' in result
        assert 'standard_headers' in result
        assert 'custom_headers' in result
        assert 'headers' in result
        
        # Test error case - simulate file read error
        mock_open.side_effect = FileNotFoundError("File not found")
        request_text = ""
        result = tool.analyze_headers(request_text)
        assert 'error' in result                                                                                            