import os
import argparse
import yaml
from typing import Dict, Any, List

class Config:
    """Configuration manager for the C2 server"""
    
    def __init__(self):
        self.config = {
            'bind_address': '0.0.0.0',
            'ssh_port': 2222,
            'http_port': 8080,
            'host_key': 'data/keys/server_key',
            'username': 'implant',
            'password': 'implant',
            'log_level': 'INFO',
            'log_file': 'logs/c2server.log',
            'download_dir': 'data/downloads',
            'knock_sequence': [10000, 10001, 10002],
            'transports': ['ssh'],  # Available: 'ssh', 'http'
        }
        
    def load_from_file(self, config_file: str) -> None:
        """Load configuration from a YAML file"""
        if not os.path.exists(config_file):
            return
            
        try:
            with open(config_file, 'r') as f:
                file_config = yaml.safe_load(f)
                if file_config:
                    self.config.update(file_config)
        except Exception as e:
            print(f"Error loading config file: {e}")
            
    def update_from_args(self, args: argparse.Namespace) -> None:
        """Update configuration from command line arguments"""
        for key, value in vars(args).items():
            if value is not None and key in self.config:
                self.config[key] = value
                
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        return self.config.get(key, default)
        
    def set(self, key: str, value: Any) -> None:
        """Set a configuration value"""
        self.config[key] = value
        
    def ensure_directories(self) -> None:
        """Ensure required directories exist"""
        directories = [
            os.path.dirname(self.get('log_file')),
            self.get('download_dir'),
            os.path.dirname(self.get('host_key'))
        ]
        
        for directory in directories:
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)

    def get_transports(self) -> List[str]:
        """Get enabled transport mechanisms"""
        return self.config.get('transports', ['ssh'])

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="C2 Server")
    parser.add_argument("--config", help="Path to config file")
    parser.add_argument("--bind-address", dest="bind_address", help="Bind address")
    parser.add_argument("--ssh-port", dest="ssh_port", type=int, help="SSH listen port")
    parser.add_argument("--http-port", dest="http_port", type=int, help="HTTP listen port")
    parser.add_argument("--host-key", dest="host_key", help="Host key file")
    parser.add_argument("--username", help="Auth username")
    parser.add_argument("--password", help="Auth password")
    parser.add_argument("--log-level", dest="log_level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Logging level")
    parser.add_argument("--transports", nargs="+", choices=["ssh", "http"], help="Enabled transport mechanisms")
    
    return parser.parse_args()

def load_config() -> Config:
    """Load and initialize configuration"""
    args = parse_arguments()
    config = Config()
    
    # Load config in order of precedence
    if args.config:
        config.load_from_file(args.config)
    
    config.update_from_args(args)
    config.ensure_directories()
    
    return config