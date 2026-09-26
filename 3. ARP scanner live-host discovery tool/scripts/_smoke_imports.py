print("importing scapy...", flush=True)
import scapy.all
print("scapy ok", flush=True)
print("importing packets...", flush=True)
from arp_scanner.core import packets
print("packets ok", flush=True)
print("importing engine...", flush=True)
from arp_scanner.core import engine
print("engine ok", flush=True)
print("importing gui...", flush=True)
from arp_scanner.gui import main_window
print("gui ok", flush=True)
print("all good", flush=True)