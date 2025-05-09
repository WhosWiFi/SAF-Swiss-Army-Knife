import pytest
from wifis_web_tool import HTTPRequestTool, Tools

@pytest.fixture
def tools():
    http_tool = HTTPRequestTool()
    return Tools(http_tool)

