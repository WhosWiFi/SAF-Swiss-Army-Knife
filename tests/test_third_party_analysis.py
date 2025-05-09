import pytest
from unittest.mock import patch, MagicMock
from wifis_web_tool import HTTPRequestTool, Third_Party_Analysis
import requests
import urllib.parse

@pytest.fixture
def third_party_analysis():
    http_tool = HTTPRequestTool()
    return Third_Party_Analysis(http_tool)

