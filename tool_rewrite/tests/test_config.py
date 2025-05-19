import pytest
from saf import Config

@pytest.fixture
def config():
    return Config()
