import pytest
from unittest.mock import patch, MagicMock
from wifis_web_tool import HTTPRequestTool, Third_Party_Analysis
import requests
import urllib.parse

@pytest.fixture
def third_party_analysis():
    http_tool = HTTPRequestTool()
    return Third_Party_Analysis(http_tool)

def test_run_testssl(third_party_analysis):
    # Mock subprocess.Popen to avoid actual system calls
    with patch('subprocess.Popen') as mock_popen:
        # Configure the mock
        mock_process = MagicMock()
        mock_process.stdout.readline.return_value = "TestSSL output line"
        mock_process.poll.return_value = 0
        mock_popen.return_value = mock_process

        # Test valid domain
        domain = "example.com"
        generator = third_party_analysis.run_testssl(domain)
        first_chunk = next(generator)
        assert 'output' in first_chunk or 'error' in first_chunk
        assert 'done' in first_chunk

        # Test invalid domain
        domain = ""
        generator = third_party_analysis.run_testssl(domain)
        first_chunk = next(generator)
        assert 'error' in first_chunk
