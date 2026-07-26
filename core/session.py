"""
BYMA TOOLS - Session Manager
Mengelola session dan navigasi apliaksi
"""
import os
from datetime import datetime


class SessionManager:
    """Manager untuk session dan navigasi"""
    
    _instance = None
    _history = []
    _current_menu = "main"
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        self._history = []
        self._current_menu = "main"
    
    def push_menu(self, menu_name):
        """Push menu ke history"""
        self._history.append(self._current_menu)
        self._current_menu = menu_name
    
    def pop_menu(self):
        """Pop menu dari history"""
        if self._history:
            self._current_menu = self._history.pop()
        return self._current_menu
    
    def get_current_menu(self):
        """Get current menu"""
        return self._current_menu
    
    def clear_history(self):
        """Clear menu history"""
        self._history = []
        self._current_menu = "main"
    
    def go_back(self):
        """Go back to previous menu"""
        return self.pop_menu()
    
    def go_main(self):
        """Go to main menu"""
        self.clear_history()
        self._current_menu = "main"
    
    def ask_continue_or_exit(self, tool_name=""):
        """Ask user to continue or exit"""
        from core.colors import cprint, Colors, print_separator
        
        print()
        print_separator("-", 50, Colors.BYELLOW)
        cprint(f"  Selesai menggunakan {tool_name}", Colors.BYELLOW)
        print_separator("-", 50, Colors.BYELLOW)
        print()
        
        options = {
            "1": "[>] Kembali ke Menu Utama",
            "2": "[<] Kembali ke Menu Sebelumnya",
            "3": "[~] Gunakan Tool Lain",
            "4": "[X] Keluar dari Program"
        }
        
        for key, value in options.items():
            cprint(f"  {key}. {value}", Colors.BWHITE)
        
        print()
        
        while True:
            try:
                choice = input("  Pilih (1-4): ").strip()
                
                if choice in options:
                    return choice
                else:
                    cprint("  [-] Pilihan tidak valid!", Colors.BRED)
            except KeyboardInterrupt:
                return "4"
    
    def ask_continue_or_back(self, tool_name=""):
        """Ask user to continue or go back"""
        from core.colors import cprint, Colors, print_separator
        
        print()
        print_separator("-", 50, Colors.BCYAN)
        
        options = {
            "1": "[>] Gunakan Tool Ini Lagi",
            "2": "[<] Kembali ke Menu Sebelumnya",
            "3": "[X] Keluar"
        }
        
        for key, value in options.items():
            cprint(f"  {key}. {value}", Colors.BWHITE)
        
        print()
        
        while True:
            try:
                choice = input("  Pilih (1-3): ").strip()
                
                if choice in options:
                    return choice
                else:
                    cprint("  [-] Pilihan tidak valid!", Colors.BRED)
            except KeyboardInterrupt:
                return "3"


# Singleton instance
session_manager = SessionManager()


def get_session_manager():
    """Get session manager instance"""
    return session_manager
