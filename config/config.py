"""
DataVault Configuration Module
Handles all configuration and API keys
"""

import json
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """Application configuration"""
    
    # App
    APP_NAME = "DataVault"
    APP_VERSION = "1.0.0"
    DEBUG = False
    
    # Paths
    BASE_DIR = Path(__file__).parent.parent
    CONFIG_DIR = BASE_DIR / "config"
    RESULTS_DIR = BASE_DIR / "results"
    
    # Create results directory if needed
    RESULTS_DIR.mkdir(exist_ok=True)
    
    # API Keys & Credentials
    IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    
    # Default settings
    TIMEOUT = 10  # Request timeout in seconds
    MAX_RETRIES = 3
    
    # UI Settings
    WINDOW_WIDTH = 1200
    WINDOW_HEIGHT = 800
    THEME = "dark"  # "light" or "dark"
    
    @classmethod
    def load_api_keys(cls):
        """Load API keys from config file"""
        config_file = cls.CONFIG_DIR / "api_keys.json"
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    keys = json.load(f)
                    cls.IPINFO_TOKEN = keys.get("ipinfo_token", "")
                    cls.VIRUSTOTAL_API_KEY = keys.get("virustotal_api_key", "")
            except Exception as e:
                print(f"Error loading API keys: {e}")
    
    @classmethod
    def save_api_keys(cls):
        """Save API keys to config file"""
        config_file = cls.CONFIG_DIR / "api_keys.json"
        keys = {
            "ipinfo_token": cls.IPINFO_TOKEN,
            "virustotal_api_key": cls.VIRUSTOTAL_API_KEY
        }
        try:
            with open(config_file, 'w') as f:
                json.dump(keys, f, indent=4)
        except Exception as e:
            print(f"Error saving API keys: {e}")


# Load API keys on import
Config.load_api_keys()
