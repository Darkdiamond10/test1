#!/usr/bin/env python3
import sys
from dark_dragon.core import DarkDragonCore

def main():
    try:
        app = DarkDragonCore()
        app.main_menu()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)

if __name__ == "__main__":
    main()
