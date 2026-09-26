"""Allow `python -m arp_scanner` to launch the GUI.""" 
from arp_scanner.app import main

if __name__ == "__main__":
    raise SystemExit(main())