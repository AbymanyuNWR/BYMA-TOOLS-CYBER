"""
BYMA TOOLS - User Manager
Sistem login, registrasi, dan session management
"""
import json
import hashlib
import os
from datetime import datetime
from pathlib import Path


class UserManager:
    """Manager untuk user authentication"""
    
    _instance = None
    _users_file = None
    _current_user = None
    _session = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._users_file is None:
            self._users_file = Path(__file__).resolve().parent.parent / "database" / "users.json"
            self._users_file.parent.mkdir(exist_ok=True)
            self._load_users()
    
    def _load_users(self):
        """Load users from file"""
        if self._users_file.exists():
            try:
                with open(self._users_file, 'r') as f:
                    self._users = json.load(f)
            except:
                self._users = {}
        else:
            self._users = {}
            self._save_users()
    
    def _save_users(self):
        """Save users to file"""
        with open(self._users_file, 'w') as f:
            json.dump(self._users, f, indent=2)
    
    def _hash_password(self, password):
        """Hash password dengan SHA256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def register(self, username, password, email=None):
        """Register user baru"""
        if username in self._users:
            return False, "Username sudah digunakan!"
        
        if len(username) < 3:
            return False, "Username minimal 3 karakter!"
        
        if len(password) < 4:
            return False, "Password minimal 4 karakter!"
        
        self._users[username] = {
            "password": self._hash_password(password),
            "email": email,
            "created_at": datetime.now().isoformat(),
            "last_login": None,
            "login_count": 0
        }
        self._save_users()
        return True, "Registrasi berhasil!"
    
    def login(self, username, password):
        """Login user"""
        if username not in self._users:
            return False, "Username tidak ditemukan!"
        
        if self._users[username]["password"] != self._hash_password(password):
            return False, "Password salah!"
        
        # Update login info
        self._users[username]["last_login"] = datetime.now().isoformat()
        self._users[username]["login_count"] += 1
        self._save_users()
        
        self._current_user = username
        self._session = {
            "username": username,
            "login_time": datetime.now().isoformat(),
            "authenticated": True
        }
        
        return True, "Login berhasil!"
    
    def logout(self):
        """Logout user"""
        self._current_user = None
        self._session = {}
        return True, "Logout berhasil!"
    
    def get_current_user(self):
        """Get current logged in user"""
        return self._current_user
    
    def is_logged_in(self):
        """Check if user is logged in"""
        return self._current_user is not None and self._session.get("authenticated")
    
    def get_user_info(self, username=None):
        """Get user info"""
        if username is None:
            username = self._current_user
        
        if username and username in self._users:
            user = self._users[username].copy()
            user.pop("password", None)  # Don't return password
            return user
        return None
    
    def list_users(self):
        """List all users (admin only)"""
        return list(self._users.keys())
    
    def delete_user(self, username):
        """Delete user"""
        if username in self._users:
            del self._users[username]
            self._save_users()
            return True, "User dihapus!"
        return False, "User tidak ditemukan!"
    
    def change_password(self, username, old_password, new_password):
        """Change user password"""
        if username not in self._users:
            return False, "User tidak ditemukan!"
        
        if self._users[username]["password"] != self._hash_password(old_password):
            return False, "Password lama salah!"
        
        if len(new_password) < 4:
            return False, "Password baru minimal 4 karakter!"
        
        self._users[username]["password"] = self._hash_password(new_password)
        self._save_users()
        return True, "Password berhasil diubah!"
    
    def has_users(self):
        """Check if any users exist"""
        return len(self._users) > 0


# Singleton instance
user_manager = UserManager()


def get_user_manager():
    """Get user manager instance"""
    return user_manager
