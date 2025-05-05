import pytest
from wifis_web_tool import HTTPRequestTool, JWTAttacks

@pytest.fixture
def jwt_attacks():
    http_tool = HTTPRequestTool()
    return JWTAttacks(http_tool)

def test_is_jwt(jwt_attacks):
    # Test valid JWT
    valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert jwt_attacks.is_jwt(valid_jwt) == True

    # Test invalid JWT
    invalid_jwt = "not.a.jwt"
    assert jwt_attacks.is_jwt(invalid_jwt) == False

def test_decode_jwt(jwt_attacks):
    # Test valid JWT
    valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = jwt_attacks.decode_jwt(valid_jwt)
    assert "Header" in result
    assert "Payload" in result

    # Test invalid JWT
    invalid_jwt = "not.a.jwt"
    result = jwt_attacks.decode_jwt(invalid_jwt)
    assert "Error" in result or "Invalid" in result

def test_find_jwt(jwt_attacks):
    # Test request with JWT in Authorization header
    request_text = "GET / HTTP/1.1\nHost: example.com\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    tokens = jwt_attacks.find_jwt(request_text)
    assert len(tokens) > 0

    # Test request without JWT
    request_text = "GET / HTTP/1.1\nHost: example.com"
    tokens = jwt_attacks.find_jwt(request_text)
    assert len(tokens) == 0

def test_unverified_signature_attack(jwt_attacks):
    # Test with valid JWT
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    request_text = "GET / HTTP/1.1\nHost: example.com\nAuthorization: Bearer " + token
    result = jwt_attacks.unverified_signature_attack(token, request_text)
    assert 'success' in result
    assert 'modified_token' in result

def test_none_signature_attack(jwt_attacks):
    # Test with valid JWT
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    request_text = "GET / HTTP/1.1\nHost: example.com\nAuthorization: Bearer " + token
    result = jwt_attacks.none_signature_attack(token, request_text)
    assert 'success' in result
    assert 'all_results' in result 