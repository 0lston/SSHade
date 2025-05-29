# C2 Server

A command and control server with multiple transport mechanisms (SSH, HTTP) for secure communications with implants.

## Features

- transport mechanisms:
  - SSH-based communication
- Interactive command line interface
- File upload and download capabilities
- Support for multiple concurrent clients
- Docker support for easy deployment

## Setup


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
- `--host-key`: Host key file (default: data/keys/server_key)
- `--username`: Auth username (default: implant)
- `--password`: Auth password (default: implant)
- `--log-level`: Logging level (default: INFO)

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

to-do

### Modifying the CLI

Modify `src/cli/command_handler.py` to add or change commands.
