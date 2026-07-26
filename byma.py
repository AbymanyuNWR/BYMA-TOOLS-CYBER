"""
BYMA TOOLS - Entry Point
This file can be used to run the tool directly
"""
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import BYMATools

def main():
    """Main entry point"""
    app = BYMATools()
    app.run()

if __name__ == "__main__":
    main()
