from flask import Flask, render_template, jsonify, request, Response
import jwt
import requests
import re
import os
from dotenv import load_dotenv
import json
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import secrets

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", secrets.token_hex(32))

# Global configuration variables
USE_HTTP = False
USE_PROXY = False
VERIFY_SSL = True
PROXIES = {}

class Config(object):
    def __init__(self):
        pass
    
    def send_request(self, request):
        try:
            request_line_by_line = request.split('\n')
            if not request_line_by_line:
                return {"error": "Empty request"}

            # Parse first line (method, path, version)
            first_line = request_line_by_line[0].split()
            if len(first_line) < 2:
                return {"error": "Invalid request format"}
            
            method = first_line[0]
            path = first_line[1]
            
            headers = {}
            current_line = 1
            while current_line < len(request_line_by_line) and request_line_by_line[current_line].strip():
                header_line = request_line_by_line[current_line].strip()
                if ':' in header_line:
                    key, value = header_line.split(':', 1)
                    headers[key.strip()] = value.strip()
                current_line += 1
            
            body = None
            if current_line < len(request_line_by_line):
                body = '\n'.join(request_line_by_line[current_line + 1:]).strip()
            
            if not path.startswith('http'):
                host = headers.get('Host', '')
                if host:
                    protocol = 'http://' if USE_HTTP else 'https://'
                    path = f"{protocol}{host}{path}"
                else:
                    return {"error": "No host specified in headers and path is not absolute URL"}
            else:
                if not USE_HTTP and path.startswith('http://'):
                    path = path.replace('http://', 'https://', 1)
                elif USE_HTTP and path.startswith('https://'):
                    path = path.replace('https://', 'http://', 1)
            
            # Configure proxy if enabled
            proxies = None
            if USE_PROXY:
                if not PROXIES:
                    return {"error": "No proxies configured"}
                
                proxy_address = next(iter(PROXIES.values()))
                protocol = proxy_address.split('://')[0]
                
                if protocol in ['http', 'https']:
                    proxies = {
                        'http': proxy_address,
                        'https': proxy_address
                    }
                else:
                    return {"error": "Invalid proxy protocol. Only HTTP and HTTPS proxies are supported"}
            
            # Send the request
            response = requests.request(
                method=method,
                url=path,
                headers=headers,
                data=body,
                verify=VERIFY_SSL,
                proxies=proxies,
                allow_redirects=False 
            )
            
            response_text = f"HTTP/{response.raw.version / 10.0} {response.status_code} {response.reason}\r\n"
            for key, value in response.headers.items():
                response_text += f"{key}: {value}\r\n"
            response_text += "\r\n"
            response_text += response.text
            
            return {
                "response": response_text
            }
            
        except Exception as e:
            return {"error": f"Error processing request: {str(e)}"}

config = Config()
    
class Tools(object):
    def __init__(self):
        pass
    
    def check_common_files(self, request):
        try:
            request_line_by_line = request.split('\n')
            if not request_line_by_line:
                return {"error": "No request found"}
            
            host = None
            for line in request_line_by_line[1:]:
                if line.lower().startswith('host:'):
                    host = line.split(':')[1].strip()
                    break
            
            if not host:
                raw_host = input("Please enter the target host (e.g. example.com): ").strip()
                try:
                    parsed = urlparse(raw_host)
                    host = parsed.netloc
                    
                    if ':' in host:
                        host = host.split(':')[0]
                        
                    if not host:
                        return {"error": "Invalid host format"}
                except Exception as e:
                    return {"error": f"Failed to parse host: {str(e)}"}
            
            protocol = "http" if USE_HTTP else "https"
            base_url = f"{protocol}://{host}"

            headers = {}
            for line in request_line_by_line[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Configure proxy if enabled
            proxies = None
            if USE_PROXY:
                if not PROXIES:
                    return {"error": "No proxies configured"}
                proxy_address = next(iter(PROXIES.values()))
                proxies = {
                    'http': proxy_address,
                    'https': proxy_address
                }
            
            with open('common_files.txt', 'r', encoding='utf-8') as common_files:
                common_files = [line.strip() for line in common_files if line.strip()]
            
            total_files = len(common_files)
            found_files = []
            checked_files = []
            consecutive_redirects = 0
            redirect_threshold = 20
            
            for file_path in common_files:
                if not file_path.startswith('/'):
                    file_path = '/' + file_path
                url = f"{base_url}{file_path}"
                try:
                    response = requests.get(
                        url, 
                        headers=headers, 
                        verify=VERIFY_SSL,
                        proxies=proxies,
                        timeout=10,
                        allow_redirects=False
                    )
                    
                    if response.status_code in [301, 302]:
                        consecutive_redirects += 1
                        if consecutive_redirects >= redirect_threshold:
                            return {
                                "warning": "False Positives are appearing in high volume, would you still like to continue the check?",
                                "total_files": total_files,
                                "total_files_checked": len(checked_files),
                                "files_found": len(found_files),
                                "found_files": found_files,
                                "checked_files": checked_files
                            }
                    else:
                        consecutive_redirects = 0
                    
                    status = {
                        "file_path": file_path,
                        "url": url,
                        "status_code": response.status_code,
                        "success": response.status_code == 200,
                        "warning": response.status_code != 404 and response.status_code != 200,
                        "icon": "bi-check-circle-fill" if response.status_code == 200 else 
                               "bi-exclamation-triangle-fill" if response.status_code != 404 else 
                               "bi-x-circle-fill",
                        "status_class": "success" if response.status_code == 200 else 
                                      "warning" if response.status_code != 404 else 
                                      "error"
                    }
                    checked_files.append(status)
                    
                    if response.status_code == 200:
                        found_files.append({
                            "file_path": file_path,
                            "url": url,
                            "response_length": len(response.text),
                            "icon": "bi-check-circle-fill",
                            "status_class": "success"
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
                "total_files": total_files,
                "total_files_checked": len(checked_files),
                "files_found": len(found_files),
                "found_files": found_files,
                "checked_files": checked_files,
                "categories": {
                    "found": [f for f in checked_files if f["status_code"] == 200],
                    "warnings": [f for f in checked_files if f["status_code"] != 404 and f["status_code"] != 200],
                    "misses": [f for f in checked_files if f["status_code"] == 404]
                }
            }
        except Exception as e:
            return {"error": f"Failed to check common files: {str(e)}"}

tools = Tools()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/toggle_http', methods=['POST'])
def toggle_http():
    global USE_HTTP
    data = request.get_json()
    USE_HTTP = data.get('use_http', False)
    return jsonify({'status': 'success', 'use_http': USE_HTTP})

@app.route('/toggle_proxy', methods=['POST'])
def toggle_proxy():
    global USE_PROXY
    data = request.get_json()
    USE_PROXY = data.get('use_proxy', False)
    return jsonify({'status': 'success', 'use_proxy': USE_PROXY})

@app.route('/toggle_verify_ssl', methods=['POST'])
def toggle_verify_ssl():
    global VERIFY_SSL
    data = request.get_json()
    VERIFY_SSL = data.get('verify_ssl', True)
    return jsonify({'status': 'success', 'verify_ssl': VERIFY_SSL})

@app.route('/add_proxy', methods=['POST'])
def add_proxy():
    global PROXIES
    data = request.get_json()
    proxy_url = data.get('proxy_url', '').strip()
    
    if not proxy_url:
        return jsonify({'error': 'Proxy URL is required'}), 400
        
    try:
        # Parse the proxy URL to get the protocol
        protocol = proxy_url.split('://')[0]
        if protocol not in ['http', 'https']:
            return jsonify({'error': 'Only HTTP and HTTPS proxies are supported'}), 400
            
        # Add the proxy to the global PROXIES dictionary
        PROXIES[protocol] = proxy_url
        return jsonify({'status': 'success', 'proxies': PROXIES})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/remove_proxy', methods=['POST'])
def remove_proxy():
    global PROXIES
    data = request.get_json()
    protocol = data.get('protocol', '').strip()
    
    if protocol in PROXIES:
        del PROXIES[protocol]
        return jsonify({
            'status': 'success', 
            'proxies': PROXIES,
            'use_proxy': USE_PROXY,
            'use_http': USE_HTTP,
            'verify_ssl': VERIFY_SSL
        })
    return jsonify({'error': 'Proxy not found'}), 404

@app.route('/get_proxies', methods=['GET'])
def get_proxies():
    return jsonify({
        'proxies': PROXIES, 
        'use_proxy': USE_PROXY,
        'use_http': USE_HTTP,
        'verify_ssl': VERIFY_SSL
    })

@app.route('/send_request', methods=['POST'])
def handle_send_request():
    data = request.get_json()
    return jsonify(config.send_request(data.get('request', '')))

@app.route('/check_common_files', methods=['GET'])
def handle_check_common_files():
    try:
        request_text = request.args.get('request_text', '')

        # Get configuration parameters
        thread_count = int(request.args.get('thread_count', 10))
        concurrent_requests = int(request.args.get('concurrent_requests', 5))
        request_timeout = int(request.args.get('request_timeout', 5))
        custom_path = request.args.get('custom_path', '')

        if not request_text:
            return jsonify({'error': 'No request text provided'}), 400

        # Parse the request to get the base URL
        lines = request_text.split('\n')
        if not lines:
            return jsonify({'error': 'Invalid request format'}), 400

        # Get headers from original request
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        # Get the first line (method and path)
        first_line = lines[0].split()
        if len(first_line) < 2:
            return jsonify({'error': 'Invalid request format'}), 400
        
        method = first_line[0]
        path = first_line[1]

        # Get host from headers
        host = headers.get('Host', '')
        if not host:
            return jsonify({'error': 'No host specified in headers'}), 400

        # Construct base URL using global HTTP setting
        protocol = 'http://' if USE_HTTP else 'https://'
        base_url = f"{protocol}{host}"

        # Configure proxy if enabled
        proxies = None
        if USE_PROXY and PROXIES:
            proxy_address = next(iter(PROXIES.values()))
            proxies = {
                'http': proxy_address,
                'https': proxy_address
            }

        # Load common files to check
        with open('common_files.txt', 'r') as f:
            common_files = [line.strip() for line in f if line.strip()]

        total_files = len(common_files)
        found_files = []
        checked_files = []

        def check_file(file_path):
            if custom_path:
                url_path = custom_path.replace('FUZZ', file_path)
            
            elif not file_path.startswith('/'):
                url_path = '/' + file_path
            else:
                url_path = file_path
            
            url = f"{base_url}{url_path}"
            print(url)
            try:
                response = requests.get(
                    url=url,
                    headers=headers,
                    verify=VERIFY_SSL,
                    proxies=proxies,
                    timeout=request_timeout,
                    allow_redirects=False
                )
                
                status = {
                    "file_path": url_path,
                    "url": url,
                    "status_code": response.status_code,
                    "success": response.status_code == 200,
                    "warning": response.status_code != 404 and response.status_code != 200,
                    "icon": "bi-check-circle-fill" if response.status_code == 200 else 
                           "bi-exclamation-triangle-fill" if response.status_code != 404 else 
                           "bi-x-circle-fill",
                    "status_class": "success" if response.status_code == 200 else 
                                  "warning" if response.status_code != 404 else 
                                  "error"
                }
                
                if response.status_code == 200:
                    found_files.append({
                        "file_path": url_path,
                        "url": url,
                        "response_length": len(response.text),
                        "icon": "bi-check-circle-fill",
                        "status_class": "success"
                    })
                
                return status
            except Exception as e:
                return {
                    "file_path": file_path,
                    "url": url,
                    "status_code": 0,
                    "success": False,
                    "error": str(e)
                }

        def generate():
            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = []
                for i in range(min(thread_count * concurrent_requests, total_files)):
                    futures.append(executor.submit(check_file, common_files[i]))
                
                current_index = thread_count * concurrent_requests
                while futures:
                    future = futures.pop(0)
                    result = future.result()
                    checked_files.append(result)
                    
                    if current_index < total_files:
                        futures.append(executor.submit(check_file, common_files[current_index]))
                        current_index += 1
                    
                    yield f"data: {json.dumps({
                        'total_files': total_files,
                        'total_files_checked': len(checked_files),
                        'files_found': len(found_files),
                        'found_files': found_files,
                        'checked_files': checked_files,
                        'categories': {
                            'found': [f for f in checked_files if f['status_code'] == 200],
                            'warnings': [f for f in checked_files if f['status_code'] != 404 and f['status_code'] != 200],
                            'misses': [f for f in checked_files if f['status_code'] == 404]
                        }
                    })}\n\n"

        return Response(generate(), mimetype='text/event-stream')

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)