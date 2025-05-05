import pytest
from wifis_web_tool import HTTPRequestTool, Tools

@pytest.fixture
def tools():
    http_tool = HTTPRequestTool()
    return Tools(http_tool)

def test_generate_clickjack(tools):
    # Test valid URL
    url = "https://example.com"
    result = tools.generate_clickjack(url)
    assert 'html' in result
    assert 'iframe' in result['html']
    assert url in result['html']

    # Test invalid URL
    url = "not-a-url"
    result = tools.generate_clickjack(url)
    assert 'html' in result
    assert 'iframe' in result['html']
    assert url in result['html'] 