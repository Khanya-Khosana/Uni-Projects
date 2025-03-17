import socket
from scapy.all import *
import time
import tkinter as tk
from tkinter import messagebox

from scapy.layers.inet import TCP, ICMP, IP


def trace_route(destination, max_hops =8, timeout=3):
    hops = [] #Intialize a list to store hop results

    try:
        # Resolve the destination domain to an ip address
        dest_ip = socket.gethostbyname(destination)
    except socket.gaierror:
        messagebox.showerror("Error", "Hostname could not be resolved")
        return

    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=dest_ip, ttl = ttl) / UDP(dport=33434)
        start_time = time.time() # recording the starting time
        reply = sr1(pkt,verbose =0 ,timeout = timeout) # send packet and wait for response

        rtt = (time.time() - start_time) * 1000 # convert to milliseconds

        if reply is None:
            hops.append(f"{ttl}: Request timeout")
        elif reply.haslayer(ICMP) and reply.getlayer(ICMP).type ==0: #reply indicates destination was reached
            hops.append(f"{ttl}: {reply.src} (RTT: {rtt:.2f} ms)")
            break
        else:
            hops.append(f"{ttl}: {reply.src} (RTT: {rtt:.2f} ms)")

    hops.append(f"Total hops: {len(hops)}")
    return hops

def start_trace_route():
    destination = entry.get() #get input from the entry widget
    if not destination:
        messagebox.showerror("Error", "Please enter a destination")
        return

#Call the traceroute function and get the results
    results = trace_route(destination)
    if results:
        output_text.delete(1.0, tk.END)
        output_text.insert(1.0, "\n".join(results))

#Create the main window for the gui
root = tk.Tk()
root.title("Trace  Application")#title

label = tk.Label(root, text="Please enter your ip address or domain name")
label.pack(pady=10)

entry = tk.Entry(root, width=50)
entry.pack(pady=10)

button = tk.Button(root, text="Start Traceroute", command=start_trace_route)
button.pack(pady=10)

output_text = tk.Text(root, height=15, width=50)
output_text.pack(pady=10)

root.mainloop()
from scapy.all import *
import time
import tkinter as tk
from tkinter import messagebox

from scapy.layers.inet import TCP
def trace_route(destination, max_hops = 30, timeout=3):
    hops = []

    try:
        dest_ip = socket.gethostbyname(destination)
    except socket.gaierror:
        messagebox.showerror("Error", "Hostname could not be resolved")
        return

    for ttl in range(1, max_hops + 1):
        start_time = time.time()
        pkt = IP(dst=dest_ip, ttl = ttl) / ICMP()
        reply = sr1(pkt,verbose =0 ,timeout = timeout)

        rtt = (time.time() - start_time) * 1000

        if reply is None:
            hops.append(f"{ttl}: Request timeout")
        elif reply and reply.haslayer(ICMP) and reply.getlayer(ICMP).type ==0:
            hops.append(f"{ttl}: {reply.src} (RTT: {rtt:.2f} ms)")
            break
        else:
            hops.append(f"{ttl}: {reply.src} (RTT: {rtt:.2f} ms)")

    hops.append(f"Total hops: {len(hops)}")
    return hops

def start_trace_route():
    destination = entry.get()
    if not destination:
        messagebox.showerror("Error", "Please enter a destination")
        return

    results = trace_route(destination)
    if results:
        output_text.delete(1.0, tk.END)
        output_text.insert(1.0, "\n".join(results))

root = tk.Tk()
root.title("Trace  Application")

label = tk.Label(root, text="Please enter your ip address or domain name")
label.pack(pady=10)

entry = tk.Entry(root, width=50)
entry.pack(pady=10)

button = tk.Button(root, text="Start Traceroute", command=start_trace_route)
button.pack(pady=10)

output_text = tk.Text(root, height=15, width=50)
output_text.pack(pady=10)

root.mainloop()
