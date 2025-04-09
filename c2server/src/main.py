import logging
import threading
import sys
import os
import signal
from typing import List

from .config import load_config
from .server.ssh_server import SSHServer
from .server.http_server import HTTPServer
from .cli.command_handler import CommandHandler

def setup_logging(log_level: str, log_file: str = None):
    """Configure logging"""
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    handlers = [logging.StreamHandler()]
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

def start_servers(config, command_handler):
    """Start the configured transport servers"""
    servers = []
    
    transports = config.get('transports', ['ssh'])
    
    if 'ssh' in transports:
        ssh_server = SSHServer(config.config, command_handler.register_client)
        try:
            ssh_server.start()
            servers.append(ssh_server)
        except Exception as e:
            logging.error(f"Failed to start SSH server: {e}")
    
    if 'http' in transports:
        http_server = HTTPServer(config.config, command_handler.register_client)
        try:
            http_server.start()
            servers.append(http_server)
        except Exception as e:
            logging.error(f"Failed to start HTTP server: {e}")
    
    return servers

def handle_signal(sig, frame):
    """Handle signals to shutdown gracefully"""
    logging.info(f"Received signal {sig}, shutting down...")
    sys.exit(0)

def main():
    """Main entry point"""
    # Load configuration
    config = load_config()
    
    # Setup logging
    setup_logging(config.get('log_level', 'INFO'), config.get('log_file'))
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    
    # Create command handler
    command_handler = CommandHandler(config.config)
    
    # Start servers
    servers = start_servers(config, command_handler)
    
    if not servers:
        logging.error("No servers started, exiting")
        sys.exit(1)
    
    # Start command interface
    try:
        command_handler.start()
    except KeyboardInterrupt:
        logging.info("Shutting down...")
    finally:
        # Stop all servers
        for server in servers:
            server.stop()
    
    logging.info("C2 server stopped")

if __name__ == "__main__":
    main()