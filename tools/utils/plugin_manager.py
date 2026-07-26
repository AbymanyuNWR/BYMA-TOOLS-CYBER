"""
BYMA TOOLS - Plugin System
System untuk menambahkan custom plugins/tools
"""
import importlib
import json
from pathlib import Path
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_section, cprint, Colors
)
from core.logger import get_logger


class PluginManager:
    """Plugin management system"""
    
    def __init__(self):
        self.logger = get_logger()
        self.plugins = {}
        self.plugin_dir = Path(__file__).resolve().parent.parent.parent / "plugins"
        self.plugin_dir.mkdir(exist_ok=True)
    
    def load_plugins(self):
        """Load all plugins from plugins directory"""
        print_info("Loading plugins...")
        
        plugin_files = list(self.plugin_dir.glob("*.py"))
        
        for plugin_file in plugin_files:
            try:
                plugin_name = plugin_file.stem
                spec = importlib.util.spec_from_file_location(plugin_name, plugin_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                if hasattr(module, 'Plugin'):
                    plugin_class = module.Plugin
                    plugin = plugin_class()
                    
                    if hasattr(plugin, 'name') and hasattr(plugin, 'description'):
                        self.plugins[plugin.name] = plugin
                        print_success(f"  Loaded plugin: {plugin.name}")
            
            except Exception as e:
                print_error(f"  Failed to load plugin {plugin_file.name}: {e}")
        
        print_info(f"Loaded {len(self.plugins)} plugins")
    
    def list_plugins(self):
        """List all available plugins"""
        print_section("Available Plugins")
        
        if not self.plugins:
            print_warning("No plugins loaded")
            return
        
        for name, plugin in self.plugins.items():
            cprint(f"    {name}: {plugin.description}", Colors.BCYAN)
            if hasattr(plugin, 'version'):
                cprint(f"      Version: {plugin.version}", Colors.BWHITE)
    
    def run_plugin(self, plugin_name, **kwargs):
        """Run a specific plugin"""
        if plugin_name not in self.plugins:
            print_error(f"Plugin not found: {plugin_name}")
            return None
        
        plugin = self.plugins[plugin_name]
        
        try:
            print_info(f"Running plugin: {plugin_name}")
            result = plugin.run(**kwargs)
            print_success(f"Plugin completed: {plugin_name}")
            return result
        except Exception as e:
            print_error(f"Plugin failed: {e}")
            return None
    
    def create_plugin_template(self, name, description):
        """Create a new plugin template"""
        template = f'''"""
{description}
"""
from core.colors import print_info, print_success, print_error


class Plugin:
    """Plugin: {name}"""
    
    def __init__(self):
        self.name = "{name}"
        self.description = "{description}"
        self.version = "1.0.0"
    
    def run(self, **kwargs):
        """Main plugin function"""
        print_info(f"Running {self.name} plugin...")
        
        # Your plugin code here
        
        print_success(f"{self.name} completed")
        return {{"status": "success"}}
'''
        
        plugin_file = self.plugin_dir / f"{name}.py"
        plugin_file.write_text(template)
        
        print_success(f"Plugin template created: {plugin_file}")
        return plugin_file
    
    def uninstall_plugin(self, plugin_name):
        """Uninstall a plugin"""
        plugin_file = self.plugin_dir / f"{plugin_name}.py"
        
        if plugin_file.exists():
            plugin_file.unlink()
            if plugin_name in self.plugins:
                del self.plugins[plugin_name]
            print_success(f"Plugin uninstalled: {plugin_name}")
        else:
            print_error(f"Plugin not found: {plugin_name}")


# Example plugin class
class ExamplePlugin:
    """Example plugin for reference"""
    
    def __init__(self):
        self.name = "example"
        self.description = "Example plugin"
        self.version = "1.0.0"
    
    def run(self, **kwargs):
        """Run plugin"""
        print_info("Example plugin running...")
        return {"status": "success"}
