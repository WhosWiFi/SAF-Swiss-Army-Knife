import pytest
from unittest.mock import patch, MagicMock
from wifis_web_tool import HTTPRequestTool, Third_Party_Analysis
import requests
import urllib.parse

@pytest.fixture
def third_party_analysis():
    http_tool = HTTPRequestTool()
    return Third_Party_Analysis(http_tool)

def test_search_wayback_machine(third_party_analysis):
    # Test with valid URL
    url = "https://example.com"
    
    # Mock requests.Session
    mock_session = MagicMock()
    
    # Mock the total pages response
    mock_pages_response = MagicMock()
    mock_pages_response.status_code = 200
    mock_pages_response.text = "1"  # Total pages
    
    # Mock the CDX API response
    mock_cdx_response = MagicMock()
    mock_cdx_response.status_code = 200
    mock_cdx_response.json.return_value = [
        ["timestamp", "original", "mimetype", "statuscode", "digest", "length"],
        ["20230101000000", "https://example.com", "text/html", "200", "abc123", "1000"]
    ]
    
    # Set up the sequence of responses
    mock_session.get.side_effect = [mock_pages_response, mock_cdx_response]
    
    with patch('requests.Session', return_value=mock_session):
        # Get the generator
        generator = third_party_analysis.search_wayback_machine(url)
        
        # Get initial message
        first_result = next(generator)
        assert 'output' in first_result
        assert 'Starting Wayback Machine search' in first_result['output']
        
        # Get page search message
        second_result = next(generator)
        assert 'output' in second_result
        assert 'Searching page' in second_result['output']
        
        # Get search results
        third_result = next(generator)
        assert 'output' in third_result
        assert 'Found URL' in third_result['output']
        
        # Get completion message
        fourth_result = next(generator)
        assert 'output' in fourth_result
        assert 'Search completed' in fourth_result['output']

def test_search_wayback_machine_error(third_party_analysis):
    # Test with invalid URL
    url = "invalid-url"
    
    # Mock requests.Session to raise an exception on the second call
    mock_session = MagicMock()
    
    # First call succeeds (total pages)
    mock_pages_response = MagicMock()
    mock_pages_response.status_code = 200
    mock_pages_response.text = "1"
    
    # Second call fails
    mock_session.get.side_effect = [mock_pages_response, requests.RequestException("Connection error")]
    
    with patch('requests.Session', return_value=mock_session):
        # Get the generator
        generator = third_party_analysis.search_wayback_machine(url)
        
        # Get initial message
        first_result = next(generator)
        assert 'output' in first_result
        assert 'Starting Wayback Machine search' in first_result['output']
        
        # Get page search message
        second_result = next(generator)
        assert 'output' in second_result
        assert 'Searching page' in second_result['output']
        
        # Get error message
        third_result = next(generator)
        assert 'error' in third_result
        assert 'Failed to connect to Wayback Machine' in third_result['error']

def test_search_wayback_machine_rate_limit(third_party_analysis):
    # Test rate limiting
    url = "https://example.com"
    
    # Mock requests.Session
    mock_session = MagicMock()
    
    # First call succeeds (total pages)
    mock_pages_response = MagicMock()
    mock_pages_response.status_code = 200
    mock_pages_response.text = "1"
    
    # Second call gets rate limited
    mock_rate_limit_response = MagicMock()
    mock_rate_limit_response.status_code = 429
    
    # Set up the sequence of responses
    mock_session.get.side_effect = [mock_pages_response, mock_rate_limit_response]
    
    with patch('requests.Session', return_value=mock_session):
        # Get the generator
        generator = third_party_analysis.search_wayback_machine(url)
        
        # Get initial message
        first_result = next(generator)
        assert 'output' in first_result
        assert 'Starting Wayback Machine search' in first_result['output']
        
        # Get page search message
        second_result = next(generator)
        assert 'output' in second_result
        assert 'Searching page' in second_result['output']
        
        # Get rate limit message
        third_result = next(generator)
        assert 'output' in third_result
        assert 'Rate limited' in third_result['output']
