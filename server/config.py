# server/config.py

SERVER_HOST = "0.0.0.0"  # Listen on all interfaces
SERVER_PORT = 2222       # Port for incoming SSH connections
USERNAME = "implant"     # Username for authentication
PASSWORD = "implant-password"  # Password for authentication
LOG_FILE = "logs/server.log"   # Path to log file
HOST_KEY_PATH = "server/host_key"  # Path to the server's private key