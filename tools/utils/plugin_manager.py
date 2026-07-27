"""
BYMA TOOLS - Advanced Plugin Manager
Professional plugin management system
"""
import json
import os
import importlib
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_database, get_logger


class PluginManager:
    """Professional plugin manager for BYMA TOOLS"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.plugins = {}
        self.plugin_dir = Path(__file__).parent.parent.parent / 'plugins'
    
    # Built-in plugins
    BUILTIN_PLUGINS = {
        'nmap_scanner': {
            'name': 'Nmap Scanner',
            'description': 'Nmap integration for advanced port scanning',
            'version': '1.0.0',
            'author': 'BYMA TOOLS',
            'category': 'recon',
            'enabled': True,
            'requires': ['nmap'],
        },
        'nikto_scanner': {
            'name': 'Nikto Scanner',
            'description': 'Nikto integration for web server scanning',
            'version': '1.0.0',
            'author': 'BYMA TOOLS',
            'category': 'scanner',
            'enabled': True,
            'requires': ['nikto'],
        },
        'sqlmap_integration': {
            'name': 'SQLMap Integration',
            'description': 'SQLMap integration for SQL injection testing',
            'version': '1.0.0',
            'author': 'BYMA TOOLS',
            'category': 'exploit',
            'enabled': True,
            'requires': ['sqlmap'],
        },
        'hydra_integration': {
            'name': 'Hydra Integration',
            'description': 'Hydra integration for brute force attacks',
            'version': '1.0.0',
            'author': 'BYMA TOOLS',
            'category': 'password',
            'enabled': True,
            'requires': ['hydra'],
        },
        'metasploit_connector': {
            'name': 'Metasploit Connector',
            'description': 'Metasploit Framework integration',
            'version': '1.0.0',
            'author': 'BYMA TOOLS',
            'category': 'exploit',
            'enabled': False,
            'requires': ['msfconsole'],
        },
    }
    
    def list_plugins(self, output=None):
        """List all plugins"""
        print_section("PLUGIN MANAGER")
        print()
        
        print_subsection("Available Plugins")
        
        # Combine built-in and custom plugins
        all_plugins = self.BUILTIN_PLUGINS.copy()
        
        # Scan for custom plugins
        self._scan_custom_plugins(all_plugins)
        
        # Display plugins
        table_data = [["Plugin", "Version", "Category", "Status", "Description"]]
        
        for name, info in all_plugins.items():
            status = "Enabled" if info.get('enabled', True) else "Disabled"
            table_data.append([
                name,
                info.get('version', '1.0.0'),
                info.get('category', 'Unknown'),
                status,
                info.get('description', '')[:40],
            ])
        
        print_table(table_data)
        print()
        
        # Summary
        total = len(all_plugins)
        enabled = sum(1 for p in all_plugins.values() if p.get('enabled', True))
        
        print(f"  {Icons.INFO} {Colors.BCYAN}Total Plugins:{Colors.BWHITE}    {total}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Enabled:{Colors.BWHITE}         {enabled}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Disabled:{Colors.BWHITE}        {total - enabled}")
        print()
        
        return all_plugins
    
    def enable(self, plugin_name, output=None):
        """Enable a plugin"""
        print_section("ENABLE PLUGIN")
        print()
        
        if plugin_name in self.BUILTIN_PLUGINS:
            self.BUILTIN_PLUGINS[plugin_name]['enabled'] = True
            print_success(f"Plugin '{plugin_name}' enabled")
        else:
            print_error(f"Plugin '{plugin_name}' not found")
    
    def disable(self, plugin_name, output=None):
        """Disable a plugin"""
        print_section("DISABLE PLUGIN")
        print()
        
        if plugin_name in self.BUILTIN_PLUGINS:
            self.BUILTIN_PLUGINS[plugin_name]['enabled'] = False
            print_success(f"Plugin '{plugin_name}' disabled")
        else:
            print_error(f"Plugin '{plugin_name}' not found")
    
    def install(self, plugin_path, output=None):
        """Install a plugin"""
        print_section("INSTALL PLUGIN")
        print()
        
        try:
            plugin_path = Path(plugin_path)
            
            if not plugin_path.exists():
                print_error(f"Plugin not found: {plugin_path}")
                return False
            
            # Validate plugin
            if not self._validate_plugin(plugin_path):
                print_error("Invalid plugin format")
                return False
            
            # Copy plugin to plugins directory
            self.plugin_dir.mkdir(parents=True, exist_ok=True)
            
            dest = self.plugin_dir / plugin_path.name
            
            import shutil
            shutil.copy2(plugin_path, dest)
            
            print_success(f"Plugin installed to {dest}")
            return True
        
        except Exception as e:
            print_error(f"Installation failed: {e}")
            return False
    
    def uninstall(self, plugin_name, output=None):
        """Uninstall a plugin"""
        print_section("UNINSTALL PLUGIN")
        print()
        
        plugin_file = self.plugin_dir / f"{plugin_name}.py"
        
        if plugin_file.exists():
            plugin_file.unlink()
            print_success(f"Plugin '{plugin_name}' uninstalled")
            return True
        else:
            print_error(f"Plugin '{plugin_name}' not found")
            return False
    
    def _scan_custom_plugins(self, plugins):
        """Scan for custom plugins"""
        if not self.plugin_dir.exists():
            return
        
        for plugin_file in self.plugin_dir.glob("*.py"):
            if plugin_file.name.startswith('_'):
                continue
            
            plugin_name = plugin_file.stem
            
            # Try to load plugin info
            try:
                spec = importlib.util.spec_from_file_location(plugin_name, plugin_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                if hasattr(module, 'PLUGIN_INFO'):
                    plugins[plugin_name] = module.PLUGIN_INFO
                else:
                    plugins[plugin_name] = {
                        'name': plugin_name,
                        'description': 'Custom plugin',
                        'version': '1.0.0',
                        'category': 'custom',
                        'enabled': True,
                    }
            except:
                plugins[plugin_name] = {
                    'name': plugin_name,
                    'description': 'Custom plugin (load error)',
                    'version': '1.0.0',
                    'category': 'custom',
                    'enabled': False,
                }
    
    def _validate_plugin(self, plugin_path):
        """Validate plugin format"""
        try:
            spec = importlib.util.spec_from_file_location("plugin", plugin_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Check for required attributes
            if not hasattr(module, 'PLUGIN_INFO'):
                print_warning("Plugin missing PLUGIN_INFO")
            
            return True
        except Exception as e:
            print_error(f"Plugin validation failed: {e}")
            return False
