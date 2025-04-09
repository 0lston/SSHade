# C2 Server

A command and control server with multiple transport mechanisms (SSH, HTTP) for secure communications with implants.

## Features

- Multiple transport mechanisms:
  - SSH-based communication
  - HTTP-based communication
- Interactive command line interface
- File upload and download capabilities
- Support for multiple concurrent clients
- Docker support for easy deployment

## Setup

### Requirements

- Python 3.8+
- Docker (optional)

### Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd c2server
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Create required directories:
   ```
   mkdir -p logs data/downloads data/keys
   ```

## Usage

### Running directly

```
python -m src.main
```

Command line arguments:
- `--config`: Path to config file
- `--bind-address`: Bind address (default: 0.0.0.0)
- `--ssh-port`: SSH listen port (default: 2222)
- `--http-port`: HTTP listen port (default: 8080)
- `--host-key`: Host key file (default: data/keys/server_key)
- `--username`: Auth username (default: implant)
- `--password`: Auth password (default: implant)
- `--log-level`: Logging level (default: INFO)
- `--transports`: Enabled transport mechanisms (choices: ssh, http)

### Running with Docker

```
docker-compose up -d
```

To access the CLI:
```
docker attach c2server_c2server_1
```

## CLI Commands

- `clients`: List all connected clients
- `use <id>`: Switch to a specific client
- `info`: Show detailed info about current client
- `shell`: Enter interactive shell mode with current client
- `upload <local> <remote>`: Upload a file to the client
- `download <remote>`: Download a file from the client
- `help`: Show help message
- `exit`: Exit the command interface
- Any other command will be sent to the current client

## Directory Structure

- `src/`: Source code
  - `server/`: Transport implementations
  - `session/`: Client session management
  - `cli/`: Command line interface
  - `utils/`: Utilities
- `logs/`: Log files
- `data/`: Data files
  - `keys/`: SSH keys
  - `downloads/`: Downloaded files

## Extending the Server

### Adding a New Transport

1. Create a new file in `src/server/` (e.g., `dns_server.py`)
2. Implement the transport by extending `BaseServer`
3. Add the transport to the list of available transports in `config.py`
4. Update `main.py` to initialize the new transport

### Modifying the CLI

Modify `src/cli/command_handler.py` to add or change commands.