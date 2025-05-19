from flask import Flask, render_template, jsonify, request
import jwt
import requests
import re
import os
from dotenv import load_dotenv
import json
from urllib.parse import urlparse

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY")

# Global configuration variables
USE_HTTP = False
USE_PROXY = False
VERIFY_SSL = True
PROXIES = {}

class Config(object):
    def __init__(self):
        pass
    
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
                return {"error": "Could not determine host"}
            
            protocol = "http" if USE_HTTP else "https"
            base_url = f"{protocol}://{host}"

            headers = {}
            for line in request_line_by_line[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            proxies = None
            if USE_PROXY:
                if not PROXIES:
                    return {"error": "No Proxies Added"}
                proxies = PROXIES
            
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
                        "warning": response.status_code != 404 and response.status_code != 200
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

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/toggle_http', methods=['POST'])
def toggle_http():
    global USE_HTTP
    data = request.get_json()
    USE_HTTP = data.get('use_http', False)
    return

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
        if protocol not in ['http', 'https', 'ftp', 'socks4', 'socks5']:
            return jsonify({'error': 'Invalid proxy protocol'}), 400
            
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
        return jsonify({'status': 'success', 'proxies': PROXIES})
    return jsonify({'error': 'Proxy not found'}), 404

@app.route('/get_proxies', methods=['GET'])
def get_proxies():
    return jsonify({
        'proxies': PROXIES, 
        'use_proxy': USE_PROXY,
        'verify_ssl': VERIFY_SSL
    })

if __name__ == '__main__':
    app.run()