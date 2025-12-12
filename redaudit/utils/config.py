#!/usr/bin/env python3
"""
RedAudit - Configuration Management Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v3.0.1: Persistent configuration for NVD API key and other settings.
"""

import os
import json
import stat
from typing import Dict, Optional, Any

# Config paths
CONFIG_DIR = os.path.expanduser("~/.redaudit")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
CONFIG_VERSION = "3.0.1"

# Environment variable names
ENV_NVD_API_KEY = "NVD_API_KEY"

# Default config structure
DEFAULT_CONFIG = {
    "version": CONFIG_VERSION,
    "nvd_api_key": None,
    "nvd_api_key_storage": None,  # "config", "env", or None
}


def ensure_config_dir() -> str:
    """
    Create config directory if it doesn't exist.
    
    Returns:
        Path to config directory
    """
    if not os.path.isdir(CONFIG_DIR):
        os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
    return CONFIG_DIR


def load_config() -> Dict[str, Any]:
    """
    Load configuration from file.
    
    Returns:
        Configuration dictionary (defaults if file doesn't exist)
    """
    ensure_config_dir()
    
    if not os.path.isfile(CONFIG_FILE):
        return DEFAULT_CONFIG.copy()
    
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # Merge with defaults for any missing keys
        merged = DEFAULT_CONFIG.copy()
        merged.update(config)
        return merged
        
    except (json.JSONDecodeError, IOError):
        return DEFAULT_CONFIG.copy()


def save_config(config: Dict[str, Any]) -> bool:
    """
    Save configuration to file with secure permissions.
    
    Args:
        config: Configuration dictionary to save
        
    Returns:
        True if save succeeded
    """
    ensure_config_dir()
    
    # Ensure version is current
    config["version"] = CONFIG_VERSION
    
    try:
        # Write to temp file first then rename (atomic)
        temp_file = CONFIG_FILE + ".tmp"
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        
        # Set secure permissions (owner read/write only)
        os.chmod(temp_file, stat.S_IRUSR | stat.S_IWUSR)
        
        # Atomic rename
        os.replace(temp_file, CONFIG_FILE)
        return True
        
    except (IOError, OSError):
        return False


def get_nvd_api_key() -> Optional[str]:
    """
    Get NVD API key from config file or environment variable.
    
    Priority:
    1. Environment variable NVD_API_KEY
    2. Config file ~/.redaudit/config.json
    
    Returns:
        API key string or None if not configured
    """
    # Check environment variable first
    env_key = os.environ.get(ENV_NVD_API_KEY)
    if env_key and env_key.strip():
        return env_key.strip()
    
    # Then check config file
    config = load_config()
    file_key = config.get("nvd_api_key")
    if file_key and file_key.strip():
        return file_key.strip()
    
    return None


def set_nvd_api_key(api_key: str, storage: str = "config") -> bool:
    """
    Store NVD API key in config file.
    
    Args:
        api_key: The API key to store
        storage: Storage method ("config" for file)
        
    Returns:
        True if save succeeded
    """
    config = load_config()
    config["nvd_api_key"] = api_key.strip() if api_key else None
    config["nvd_api_key_storage"] = storage
    return save_config(config)


def clear_nvd_api_key() -> bool:
    """
    Remove NVD API key from config file.
    
    Returns:
        True if save succeeded
    """
    config = load_config()
    config["nvd_api_key"] = None
    config["nvd_api_key_storage"] = None
    return save_config(config)


def is_nvd_api_key_configured() -> bool:
    """
    Check if NVD API key is configured (either env or config).
    
    Returns:
        True if API key is available
    """
    return get_nvd_api_key() is not None


def validate_nvd_api_key(api_key: str) -> bool:
    """
    Validate NVD API key format.
    
    NVD API keys are UUIDs: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    
    Args:
        api_key: The API key to validate
        
    Returns:
        True if format appears valid
    """
    if not api_key:
        return False
    
    key = api_key.strip()
    
    # UUID format: 8-4-4-4-12 hex characters
    parts = key.split("-")
    if len(parts) != 5:
        return False
    
    expected_lengths = [8, 4, 4, 4, 12]
    for i, part in enumerate(parts):
        if len(part) != expected_lengths[i]:
            return False
        if not all(c in "0123456789abcdefABCDEF" for c in part):
            return False
    
    return True


def get_config_summary() -> Dict[str, Any]:
    """
    Get a summary of current configuration status.
    
    Returns:
        Dictionary with config status info
    """
    config = load_config()
    
    has_env_key = bool(os.environ.get(ENV_NVD_API_KEY))
    has_file_key = bool(config.get("nvd_api_key"))
    
    return {
        "config_file": CONFIG_FILE,
        "config_exists": os.path.isfile(CONFIG_FILE),
        "nvd_key_source": "env" if has_env_key else ("config" if has_file_key else None),
        "nvd_key_configured": has_env_key or has_file_key,
    }
