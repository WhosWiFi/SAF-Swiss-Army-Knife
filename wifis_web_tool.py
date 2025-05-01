from flask import Flask, render_template, request, jsonify, session
import jwt
import json
import requests
import re
import subprocess
import os
from urllib.parse import urlparse, parse_qs
import base64
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import time

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session management

class HTTPRequestTool:
    def __init__(self):
        self.jwt_attacks = JWTAttacks(self)
        self.tools = Tools(self)
        self.third_party_analysis = Third_Party_Analysis(self)
        
        # Load header information from JSON file
        try:
            with open('http_headers.json', 'r', encoding='utf-8') as f:
                header_data = json.load(f)
                self.request_headers = header_data['request_headers']
                self.response_headers = header_data['response_headers']
        except Exception as e:
            print(f"Failed to load header information: {str(e)}")
            self.request_headers = {}
            self.response_headers = {}
        
        # Load common files from common_files.txt
        try:
            with open('common_files.txt', 'r', encoding='utf-8') as f:
                self.common_files = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Failed to load common files: {str(e)}")
            self.common_files = []

    def check_common_files(self, request_text, use_proxy=False, proxy_address=None, verify_cert=True):
        try:
            # Parse the request to get the base URL
            request_lines = request_text.split('\n')
            if not request_lines:
                return {"error": "No request found"}
            
            # Get the first line (method and path)
            first_line = request_lines[0].split()
            if len(first_line) < 2:
                return {"error": "Invalid request format"}
            
            # Get the full URL
            full_url = first_line[1]
            if not full_url.startswith('http'):
                # If host header exists, use it to construct full URL
                host = None
                for line in request_lines[1:]:
                    if line.lower().startswith('host:'):
                        host = line.split(':', 1)[1].strip()
                        break
                
                if not host:
                    return {"error": "Could not determine host"}
                
                # Always use HTTPS
                full_url = f"https://{host}{full_url}"
            
            # Parse URL to get base
            parsed_url = urlparse(full_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Get headers from original request
            headers = {}
            for line in request_lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Configure proxy if enabled
            proxies = None
            verify = True
            if use_proxy:
                if not proxy_address:
                    return {"error": "Please enter a proxy address"}
                proxies = {
                    'http': proxy_address,
                    'https': proxy_address
                }
                verify = verify_cert
            
            found_files = []
            checked_files = []
            for file_path in self.common_files:
                # Try the file path
                url = f"{base_url}{file_path}"
                try:
                    response = requests.get(
                        url, 
                        headers=headers, 
                        verify=verify,
                        proxies=proxies,
                        timeout=5,
                        allow_redirects=False
                    )
                    status = {
                        "file_path": file_path,
                        "url": url,
                        "status_code": response.status_code,
                        "success": response.status_code == 200
                    }
                    checked_files.append(status)
                    
                    if response.status_code == 200:
                        found_files.append({
                            "file_path": file_path,
                            "url": url,
                            "response_length": len(response.text)
                        })
                except Exception as e:
                    checked_files.append({
                        "file_path": file_path,
                        "url": url,
                        "status_code": 0,
                        "success": False,
                        "error": str(e)
                    })
            
            return {
                "total_files_checked": len(self.common_files),
                "files_found": len(found_files),
                "found_files": found_files,
                "checked_files": checked_files
            }
        except Exception as e:
            return {"error": f"Failed to check common files: {str(e)}"}

    def process_request(self, request_text, use_proxy=False, proxy_address=None, verify_cert=True):
        try:
            # Parse the raw HTTP request
            request_lines = request_text.split('\n')
            if not request_lines:
                return {"error": "Empty request"}

            # Parse first line (method, path, version)
            first_line = request_lines[0].split()
            if len(first_line) < 2:
                return {"error": "Invalid request format"}
            
            method = first_line[0]
            path = first_line[1]
            
            # Parse headers
            headers = {}
            current_line = 1
            while current_line < len(request_lines) and request_lines[current_line].strip():
                header_line = request_lines[current_line].strip()
                if ':' in header_line:
                    key, value = header_line.split(':', 1)
                    headers[key.strip()] = value.strip()
                current_line += 1
            
            # Get body if exists (after blank line)
            body = None
            if current_line < len(request_lines):
                body = '\n'.join(request_lines[current_line + 1:]).strip()
            
            # Parse URL and enforce HTTPS
            if not path.startswith('http'):
                # If host header exists, use it to construct full URL
                host = headers.get('Host', '')
                if host:
                    # Always use HTTPS
                    path = f"https://{host}{path}"
                else:
                    return {"error": "No host specified in headers and path is not absolute URL"}
            else:
                # If URL starts with http://, change it to https://
                if path.startswith('http://'):
                    path = path.replace('http://', 'https://', 1)
            
            # Configure proxy if enabled
            proxies = None
            verify = True
            if use_proxy:
                if not proxy_address:
                    return {"error": "Please enter a proxy address"}
                
                # Ensure proxy address is properly formatted for Burp Suite
                if not proxy_address.startswith(('http://', 'https://')):
                    proxy_address = 'http://' + proxy_address
                
                proxies = {
                    'http': proxy_address,
                    'https': proxy_address
                }
                verify = verify_cert
                
                # Test proxy connection
                try:
                    test_response = requests.get('https://example.com', proxies=proxies, verify=verify, timeout=5)
                except requests.exceptions.ProxyError:
                    return {"error": "Could not connect to Burp Suite proxy. Please ensure Burp Suite is running and listening on the specified port."}
                except requests.exceptions.SSLError:
                    return {"error": "SSL verification failed. Try unchecking 'Verify Proxy Cert' or importing Burp Suite's CA certificate."}
                except Exception as e:
                    return {"error": f"Error connecting to proxy: {str(e)}"}
            
            # Send the request
            response = requests.request(
                method=method,
                url=path,
                headers=headers,
                data=body,
                verify=verify,
                proxies=proxies,
                allow_redirects=False  # Don't follow redirects to see the actual response
            )
            
            # Format response like Burp Suite
            response_text = f"HTTP/{response.raw.version / 10.0} {response.status_code} {response.reason}\r\n"
            for key, value in response.headers.items():
                response_text += f"{key}: {value}\r\n"
            response_text += "\r\n"
            response_text += response.text
            
            # Find JWT tokens in the request
            jwt_tokens = self.jwt_attacks.find_jwt(request_text)
            jwt_decoded = ""
            if jwt_tokens:
                for i, token in enumerate(jwt_tokens, 1):
                    jwt_decoded += f"JWT #{i}:\n{self.jwt_attacks.decode_jwt(token)}\n\n"
            
            return {
                "response": response_text,
                "jwt_tokens": jwt_decoded
            }
            
        except Exception as e:
            return {"error": f"Error processing request: {str(e)}"}

class JWTAttacks:
    def __init__(self, http_request_tool):
        self.http_request_tool = http_request_tool

    def is_jwt(self, token):
        # Split the token into parts
        parts = token.split('.')
        
        # We only care about header and body
        if len(parts) < 2:
            return False
            
        try:
            # Check if header and body are valid base64
            for part in parts[:2]:  # Only check header and body
                if part:  # Skip empty parts
                    # Add padding if needed
                    padding = 4 - (len(part) % 4)
                    if padding != 4:
                        part += '=' * padding
                    decoded = base64.b64decode(part)
                    # Try to parse as JSON to verify structure
                    json.loads(decoded)
            return True
        except:
            return False

    def decode_jwt(self, token):
        try:
            # Split the token into parts
            parts = token.split('.')
            
            # We only care about header and body
            if len(parts) < 2:
                return "Invalid JWT format"
            
            # Decode header and body
            decoded_parts = []
            for part in parts[:2]:  # Only process header and body
                if part:
                    # Add padding if needed
                    padding = 4 - (len(part) % 4)
                    if padding != 4:
                        part += '=' * padding
                    decoded = base64.b64decode(part)
                    try:
                        # Try to parse as JSON
                        decoded_parts.append(json.loads(decoded))
                    except:
                        # If not JSON, just use the decoded string
                        decoded_parts.append(decoded.decode('utf-8'))
            
            # Format the output
            output = []
            if len(decoded_parts) >= 1:
                output.append(f"Header:\n{json.dumps(decoded_parts[0], indent=2)}")
            if len(decoded_parts) >= 2:
                output.append(f"\nPayload:\n{json.dumps(decoded_parts[1], indent=2)}")
                
            return '\n'.join(output)
        except Exception as e:
            return f"Error decoding JWT: {str(e)}"

    def find_jwt(self, request_text):
        # Split request into words and check each for JWT pattern
        tokens = []
        seen_tokens = set()  # Track seen tokens to avoid duplicates
        
        # Find all potential JWT patterns in the text
        # This regex looks for base64 strings separated by dots, allowing for more flexible patterns
        jwt_pattern = r'(?:Bearer\s+)?([A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+(?:\.[A-Za-z0-9-_=]+)?)'
        
        # Look for JWTs in headers and cookies
        for line in request_text.split('\n'):
            # Check for Authorization header
            if 'Authorization:' in line:
                matches = re.findall(jwt_pattern, line)
                for token in matches:
                    if token not in seen_tokens and self.is_jwt(token):
                        tokens.append(token)
                        seen_tokens.add(token)
            
            # Check for Cookie header with more flexible pattern matching
            if 'Cookie:' in line:
                # Look for any cookie that might contain a JWT
                cookie_pairs = line.split(':', 1)[1].strip().split(';')
                for pair in cookie_pairs:
                    cookie_name, cookie_value = pair.strip().split('=', 1) if '=' in pair else (None, pair.strip())
                    if cookie_value:
                        matches = re.findall(jwt_pattern, cookie_value)
                        for token in matches:
                            if token not in seen_tokens and self.is_jwt(token):
                                tokens.append(token)
                                seen_tokens.add(token)
            
            # Check for other potential JWT-containing headers
            if ':' in line:
                header_value = line.split(':', 1)[1].strip()
                matches = re.findall(jwt_pattern, header_value)
                for token in matches:
                    if token not in seen_tokens and self.is_jwt(token):
                        tokens.append(token)
                        seen_tokens.add(token)
        
        # Also check the entire text for any JWTs we might have missed
        # This includes looking for JWTs in query parameters and other parts of the request
        all_matches = re.findall(jwt_pattern, request_text)
        for token in all_matches:
            if token not in seen_tokens and self.is_jwt(token):
                tokens.append(token)
                seen_tokens.add(token)
        
        # Return all found JWTs
        return tokens

class Tools:
    def __init__(self, http_request_tool):
        self.http_request_tool = http_request_tool
    
    def generate_clickjack(self, url):
        clickjack_html = f"""<html>
   <head>
      <title>Aon Clickjacking Example PoC</title>
      <style>
         body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
         }}
         .container {{
            max-width: 1200px;
            margin: 0 auto;
         }}
         h1 {{
            color: #333;
            margin-bottom: 20px;
         }}
         .iframe-container {{
            position: relative;
            width: 100%;
            height: 80vh;
         }}
         iframe {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.5;
            border: 2px solid #333;
         }}
      </style>
   </head>
   <body>
      <div class="container">
         <h1>Aon Clickjacking PoC</h1>
         <div class="iframe-container">
            <iframe src="{url}"></iframe>
         </div>
      </div>
   </body>
</html>"""
        return {"html": clickjack_html}

class Third_Party_Analysis:
    def __init__(self, http_request_tool):
        self.http_request_tool = http_request_tool
    
    def run_testssl(self, domain):
        try:
            # Store current directory
            current_dir = os.getcwd()
            
            # Change to testssl directory
            os.chdir('testssl')
            
            # Make sure testssl.sh is executable
            os.chmod('testssl.sh', 0o755)
            
            # Run testssl.sh with HTML output using system OpenSSL
            process = subprocess.Popen(
                ['./testssl.sh', '--html', domain],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Read output in real-time
            output = []
            while True:
                line = process.stdout.readline()
                if line == '' and process.poll() is not None:
                    break
                if line:
                    # Remove any ANSI codes
                    line = re.sub(r'\033\[[0-9;]*m', '', line)
                    output.append(line)
            
            # Get any remaining output
            stdout, stderr = process.communicate()
            
            # Change back to original directory
            os.chdir(current_dir)
            
            # Add any remaining output
            if stdout:
                output.extend(stdout.splitlines())
            if stderr:
                output.extend([f"Error: {line}" for line in stderr.splitlines()])
            
            return {"output": output}
            
        except Exception as e:
            return {"error": f"Failed to run TestSSL: {str(e)}"}

    def search_wayback_machine(self, url):
        try:
            # Extract domain from URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Configure session with retries and longer timeout
            session = requests.Session()
            retry = requests.adapters.HTTPAdapter(max_retries=3)
            session.mount('https://', retry)
            session.mount('http://', retry)
            
            # Initialize variables for pagination
            page = 0
            page_size = 50  # Default page size
            all_results = []
            max_results = 150000  # Maximum results limit
            
            # First get total number of pages
            num_pages_url = f"https://web.archive.org/cdx/search/cdx?url={domain}&matchType=domain&output=json&showNumPages=true"
            try:
                num_pages_response = session.get(num_pages_url, timeout=60)
                if num_pages_response.status_code == 200:
                    total_pages = int(num_pages_response.text.strip())
                else:
                    total_pages = 1  # Fallback if we can't get total pages
            except:
                total_pages = 1  # Fallback if we can't get total pages
            
            # Initialize progress tracking
            progress = {
                "current_page": 0,
                "total_pages": total_pages,
                "results_found": 0,
                "status": "searching"
            }
            
            while page < total_pages and len(all_results) < max_results:
                # Update progress
                progress["current_page"] = page
                progress["results_found"] = len(all_results)
                
                # Construct the Wayback Machine CDX API URL with proper format and pagination
                wayback_url = f"https://web.archive.org/cdx/search/cdx?url={domain}&matchType=domain&output=json&fl=timestamp,original,mimetype,statuscode,digest,length&collapse=urlkey&page={page}&pageSize={page_size}"
                
                try:
                    # Send request to Wayback Machine API with longer timeout
                    response = session.get(wayback_url, timeout=60)
                    
                    if response.status_code == 429:  # Too Many Requests
                        progress["status"] = "rate_limited"
                        time.sleep(5)  # Wait 5 seconds before retrying
                        continue
                    
                    if response.status_code != 200:
                        progress["status"] = "error"
                        return {
                            "error": f"Failed to fetch data from Wayback Machine (Status code: {response.status_code})",
                            "progress": progress
                        }
                    
                    # Parse the JSON response
                    data = response.json()
                    if not data or len(data) <= 1:  # First row is headers
                        break
                    
                    # Process results
                    for row in data[1:]:
                        try:
                            timestamp, original, mimetype, statuscode, digest, length = row
                            if not all([timestamp, original, mimetype, statuscode, digest, length]):
                                continue
                            
                            # Add result to collection
                            all_results.append({
                                "timestamp": timestamp,
                                "original": original,
                                "mimetype": mimetype,
                                "statuscode": statuscode,
                                "length": length
                            })
                            
                            # Check if we've reached the maximum results
                            if len(all_results) >= max_results:
                                break
                            
                        except:
                            continue
                    
                    # Move to next page
                    page += 1
                    
                    # Add a small delay between requests to avoid rate limiting
                    time.sleep(1)
                    
                except requests.Timeout:
                    progress["status"] = "timeout"
                    time.sleep(5)  # Wait 5 seconds before retrying
                    continue
                except requests.RequestException as e:
                    progress["status"] = "error"
                    return {
                        "error": f"Failed to connect to Wayback Machine: {str(e)}",
                        "progress": progress
                    }
            
            progress["status"] = "completed"
            return {
                "total_results": len(all_results),
                "results": all_results,
                "progress": progress
            }
            
        except Exception as e:
            return {
                "error": f"Failed to search Wayback Machine: {str(e)}",
                "progress": {"status": "error"}
            }

# Initialize the HTTP request tool
http_tool = HTTPRequestTool()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process_request', methods=['POST'])
def process_request():
    data = request.get_json()
    return jsonify(http_tool.process_request(
        data.get('request_text', ''),
        data.get('use_proxy', False),
        data.get('proxy_address'),
        data.get('verify_cert', True)
    ))

@app.route('/generate_clickjack', methods=['POST'])
def generate_clickjack():
    data = request.get_json()
    return jsonify(http_tool.tools.generate_clickjack(data.get('url', '')))

@app.route('/check_common_files', methods=['POST'])
def check_common_files():
    data = request.get_json()
    return jsonify(http_tool.check_common_files(
        data.get('request_text', ''),
        data.get('use_proxy', False),
        data.get('proxy_address'),
        data.get('verify_cert', True)
    ))

@app.route('/run_testssl', methods=['POST'])
def run_testssl():
    data = request.get_json()
    return jsonify(http_tool.third_party_analysis.run_testssl(data.get('domain', '')))

@app.route('/search_wayback', methods=['POST'])
def search_wayback():
    data = request.get_json()
    return jsonify(http_tool.third_party_analysis.search_wayback_machine(data.get('url', '')))

@app.route('/decode_jwt', methods=['POST'])
def decode_jwt():
    data = request.get_json()
    token = data.get('token', '')
    return jsonify({
        "decoded": http_tool.jwt_attacks.decode_jwt(token)
    })

@app.route('/find_jwt', methods=['POST'])
def find_jwt():
    data = request.get_json()
    request_text = data.get('request_text', '')
    tokens = http_tool.jwt_attacks.find_jwt(request_text)
    return jsonify({
        "tokens": tokens,
        "count": len(tokens)
    })

if __name__ == '__main__':
    app.run(debug=True)
