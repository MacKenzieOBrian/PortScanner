import socket
import subprocess
import sys
from datetime import datetime
from threading import Thread, Lock
from queue import Queue

# Function to grab the banner of a service
def grab_banner(sock):
    try:
        sock.send(b'HEAD / HTTP/1.1\r\n\r\n')
        banner = sock.recv(1024).decode().strip()
        return banner
    except Exception as e:
        return str(e)

# Function to scan a single port and grab the banner
def scan_port(remoteServerIP, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((remoteServerIP, port))
        if result == 0:
            banner = grab_banner(sock)
            with print_lock:
                open_ports.append(port)
                results.append(f"Port {port}: Open | Banner: {banner}")
                print(f"Port {port}: Open | Banner: {banner}")  # Immediate print for debugging
        sock.close()
    except Exception as e:
        with print_lock:
            print(f"Error scanning port {port}: {e}")

# Thread worker function
def threader():
    while True:
        port = q.get()
        print(f"Scanning port {port}...")  # Debug print statement
        scan_port(remoteServerIP, port)
        q.task_done()

# Clear the screen
subprocess.call('clear', shell=True)

# Input remote host
remoteServer = input("Enter a remote host to scan: ")
remoteServerIP = socket.gethostbyname(remoteServer)

# Info about host
print("-" * 60)
print("Please wait, scanning remote host", remoteServerIP)
print("-" * 60)

# Record the start time
t1 = datetime.now()

# Create a queue and thread pool
q = Queue()
print_lock = Lock()
open_ports = []
results = []

# Start the threads
for _ in range(100):  # You can adjust the number of threads
    t = Thread(target=threader)
    t.daemon = True
    t.start()

# Assign ports to the queue
for port in range(1, 5000):  # You can extend the range if needed
    q.put(port)

# Wait for the queue to be empty
q.join()

# Record the end time
t2 = datetime.now()

# Calculate and print the total scan time
total = t2 - t1
print("Scanning completed in: ", total)

# Print the results
print("\nScan Results:")
if results:
    for result in results:
        print(result)
else:
    print("No open ports found.")
