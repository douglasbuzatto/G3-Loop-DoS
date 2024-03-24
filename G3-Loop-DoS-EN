import socket
import random
import argparse
import threading
from queue import Queue
from datetime import datetime
import cmd

class GeDosLoopShell(cmd.Cmd):
  """G3 Loop DoS Scanner"""
  intro = "Welcome to the G3 Loop DoS Scanner! Type 'help' for a list of commands."
  prompt = "(G3-Loop-DoS) "

  def __init__(self):
    super().__init__()
    self.ip_range = None
    self.ports = [123, 53, 161]  # Default ports
    self.protocols = ["ntp", "dns", "snmp"]  # Default protocols
    self.payload = None
    self.timeout = 2  # Default timeout in seconds
    self.num_threads = 10  # Default number of threads

  def do_scan(self, args):
    """Perform a vulnerability scan"""
    scan_ips(self.ip_range, self.ports, self.protocols, self.payload, self.timeout, self.num_threads)

  def do_set_target(self, args):
    """Set the scan target
    Usage: set_target <IP range>
    Example: set_target 192.168.1.0/24
    """
    try:
      import ipaddress
      self.ip_range = [str(ip) for ip in ipaddress.IPv4Network(args)]
      print(f"Target set to: {args}")
    except ValueError:
      print("Invalid IP range. Use CIDR format (e.g., 192.168.1.0/24).")

  def do_set_options(self, args):
    """Set scan options
    Usage: set_options <option1> <value1> [<option2> <value2>...]
    Available options:
      -p, --ports: Ports to scan (default: 123 53 161)
      -P, --protocols: Protocols to scan (default: ntp dns snmp)
      -c, --custom: Custom payload (use with 'custom' protocol)
      -t, --timeout: Response timeout in seconds (default: 2)
      -n, --threads: Number of threads to use (default: 10)
    """
    options = args.split()
    for i in range(0, len(options), 2):
      option = options[i]
      if i + 1 < len(options):
        value = options[i + 1]
      else:
        print(f"Missing value for option '{option}'.")
        return

      if option in ("-p", "--ports"):
        self.ports = [int(port) for port in value.split(",")]
      elif option in ("-P", "--protocols"):
        self.protocols = value.split(",")
      elif option in ("-c", "--custom"):
        if "custom" not in self.protocols:
          self.protocols.append("custom")
        self.payload = value.encode()
      elif option in ("-t", "--timeout"):
        self.timeout = int(value)
      elif option in ("-n", "--threads"):
        self.num_threads = int(value)
      else:
        print(f"Unknown option '{option}'.")

  def do_help(self, args):
    """Display help and usage examples"""
    examples = """
Usage examples:

1. Scan with default settings (NTP, DNS, and SNMP protocols):
  (G3-Loop-DoS) set_target 192.168.1.0/24
  (G3-Loop-DoS) scan

2. Scan with custom options (HTTP protocol and custom payload):
  (G3-Loop-DoS) set_target 10.0.0.0/24
  (G3-Loop-DoS) set_options -p 80 -P http,custom -c "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -t 5 -n 20
  (G3-Loop-DoS) scan

3. Scan with custom payload (custom protocol):
  (G3-Loop-DoS) set_target 172.16.0.0/16
  (G
