"""
BYMA TOOLS - Logger System
Sistem logging untuk pencatatan semua aktivitas
"""
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime


class BYMALogger:
    """Custom logger untuk BYMA TOOLS"""
    
    _instance = None
    _logger = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._logger is None:
            self._setup_logger()
    
    def _setup_logger(self):
        """Setup logger dengan file handler dan console handler"""
        # Create logger
        self._logger = logging.getLogger("BYMA")
        self._logger.setLevel(logging.DEBUG)
        
        # Create formatters
        file_formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        console_formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S"
        )
        
        # Setup log directory
        log_dir = Path(__file__).resolve().parent.parent / "database"
        log_dir.mkdir(exist_ok=True)
        log_file = log_dir / "byma.log"
        
        # File handler (rotating)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(file_formatter)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(console_formatter)
        
        # Add handlers
        self._logger.addHandler(file_handler)
        self._logger.addHandler(console_handler)
    
    def debug(self, message, module="CORE"):
        """Log debug message"""
        self._logger.debug(f"[{module}] {message}")
    
    def info(self, message, module="CORE"):
        """Log info message"""
        self._logger.info(f"[{module}] {message}")
    
    def warning(self, message, module="CORE"):
        """Log warning message"""
        self._logger.warning(f"[{module}] {message}")
    
    def error(self, message, module="CORE"):
        """Log error message"""
        self._logger.error(f"[{module}] {message}")
    
    def critical(self, message, module="CORE"):
        """Log critical message"""
        self._logger.critical(f"[{module}] {message}")
    
    def scan_start(self, tool_name, target):
        """Log scan start"""
        self.info(f"Starting scan: {tool_name} on {target}", "SCAN")
    
    def scan_complete(self, tool_name, target, results_count=0):
        """Log scan complete"""
        self.info(f"Scan complete: {tool_name} on {target} - {results_count} results", "SCAN")
    
    def scan_error(self, tool_name, target, error):
        """Log scan error"""
        self.error(f"Scan failed: {tool_name} on {target} - {error}", "SCAN")
    
    def action(self, action_type, details=""):
        """Log user action"""
        self.info(f"Action: {action_type} {details}", "ACTION")


# Singleton logger instance
logger = BYMALogger()


def get_logger(name="BYMA"):
    """Get logger instance"""
    return logger
