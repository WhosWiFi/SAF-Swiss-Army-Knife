import pytest
from wifis_web_tool import HTTPRequestTool, JWTAttacks
from unittest.mock import patch, MagicMock

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

def test_brute_force_secret(jwt_attacks):
    # Test with valid JWT
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    # Mock subprocess.run
    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = "Cracked: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c:secret123"
    
    with patch('subprocess.run', return_value=mock_process), \
         patch('os.path.exists', return_value=True), \
         patch('os.path.getsize', return_value=1000):
        result = jwt_attacks.brute_force_secret(token)
        assert 'success' in result
        assert 'secret' in result

def test_jwk_header_injection(jwt_attacks):
    # Test with valid JWT containing JWK
    token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vandrcyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = jwt_attacks.jwk_header_injection(token)
    assert 'success' in result
    assert 'modified_token' in result

def test_kid_header_traversal(jwt_attacks):
    # Test with valid JWT
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    request_text = "GET / HTTP/1.1\nHost: example.com\nAuthorization: Bearer " + token
    
    # Mock process_request to return success
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "Success"
    
    with patch.object(jwt_attacks.http_request_tool, 'process_request', return_value={'response': 'HTTP/1.1 200 OK\n\nSuccess'}):
        result = jwt_attacks.kid_header_traversal(token, request_text)
        assert 'success' in result
        assert 'all_results' in result



def test_edit_jwt(jwt_attacks):
    # Test with valid decoded JWT text
    decoded_text = """Header:
{
    "alg": "HS256",
    "typ": "JWT"
}

Payload:
{
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
}"""
    
    # Test without secret
    result = jwt_attacks.edit_jwt(decoded_text)
    assert 'success' in result
    assert 'encoded_token' in result
    
    # Test with secret
    result = jwt_attacks.edit_jwt(decoded_text, use_secret=True, secret='test_secret')
    assert 'success' in result
    assert 'encoded_token' in result 