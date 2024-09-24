import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
import threading
from ip_scanner import scan_active_ips, get_hostname
from port_scanner import scan_active_ports
from availability_checker import check_ip_availability, check_port_availability
import re

# Global variable to manage thread state
stop_thread = False

# Function to display results in the text box
def display_results(results):
    result_box.config(state=tk.NORMAL)
    result_box.delete(1.0, tk.END)
    for result in results:
        result_box.insert(tk.END, result + "\n")
    result_box.config(state=tk.DISABLED)

# Create a loading pop-up
def create_loading_popup(message):
    loading_popup = tk.Toplevel(window)
    loading_popup.title("Loading")
    loading_popup.geometry("300x100")
    loading_popup.transient(window)  # Make it a modal window
    loading_popup.grab_set()  # Block interactions with the main window

    label = ttk.Label(loading_popup, text=message)
    label.pack(pady=20)

    # Button to close the loading pop-up
    cancel_button = ttk.Button(loading_popup, text="Cancel", command=lambda: cancel_action(loading_popup))
    cancel_button.pack(pady=(0, 10))

    loading_popup.protocol("WM_DELETE_WINDOW", lambda: cancel_action(loading_popup))  # Handle close button
    loading_popup.update()  # Update the window to show the message immediately

    return loading_popup


# Function to cancel the action
def cancel_action(loading_popup):
    global stop_thread
    stop_thread = True  # Set the flag to stop scanning
    loading_popup.protocol("WM_DELETE_WINDOW", lambda: None)  # Prevent closing until scanning is done


# Progress Bar Functions
def start_progress():
    progress_bar.grid(row=5, column=0, columnspan=2, padx=10, pady=10)
    progress_bar.start()

def stop_progress():
    progress_bar.stop()
    progress_bar.grid_remove()

# Wrapper function for scanning active IPs
def run_ip_scan(loading_popup):
    global stop_thread
    stop_thread = False  # Reset the stop flag
    scan_button.config(state=tk.DISABLED)
    start_progress()
    
    active_ips = scan_active_ips()  # This function should return a list of active IPs
    results = []

    for ip in active_ips:
        if stop_thread:
            break  # Stop the action if the flag is set
        hostname = get_hostname(ip)
        results.append(f"IP: {ip}, Host: {hostname}")

    display_results(results)
    stop_progress()
    scan_button.config(state=tk.NORMAL)
    loading_popup.destroy()  # Close the loading pop-up if not aborted


# Wrapper function for scanning active ports
def run_port_scan(loading_popup):
    global stop_thread
    stop_thread = False  # Reset the stop flag
    port_button.config(state=tk.DISABLED)
    start_progress()
    
    active_ports = scan_active_ports()  # This function should return a list of active ports
    results = []

    for port in active_ports:
        if stop_thread:
            break  # Stop the action if the flag is set
        results.append(f"{port}")

    display_results(results)
    stop_progress()
    port_button.config(state=tk.NORMAL)
    loading_popup.destroy()  # Close the loading pop-up

# Function to handle IP scan button click
def start_ip_scan():
    loading_popup = create_loading_popup("Scanning Active IPs... it may take a little time.")
    threading.Thread(target=run_ip_scan, args=(loading_popup,)).start()

# Function to handle Port scan button click
def start_port_scan():
    loading_popup = create_loading_popup("Scanning Active Ports...")
    threading.Thread(target=run_port_scan, args=(loading_popup,)).start()

# Function to check IP availability
def check_ip():
    ip = ip_entry.get()
    # Regex pattern to validate the IP address
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    
    if not ip:
        messagebox.showwarning("Input Error", "Please enter an IP address.")
        return
    
    # Validate the IP format
    if not re.match(ip_pattern, ip):
        messagebox.showwarning("Input Error", "Please enter a valid IP address format (e.g., 192.168.1.1).")
        return
    
    # Check if each octet is in the valid range (0-255)
    octets = ip.split('.')
    if any(int(octet) < 0 or int(octet) > 255 for octet in octets):
        messagebox.showwarning("Input Error", "Each octet must be between 0 and 255.")
        return
    
    start_progress()
    availability = check_ip_availability(ip)
    stop_progress()
    
    if availability:
        messagebox.showinfo("IP Availability", f"The IP {ip} is available.")
    else:
        messagebox.showinfo("IP Availability", f"The IP {ip} is in use.")

# Function to check Port availability
def check_port():
    try:
        port = int(port_entry.get())
    except ValueError:
        messagebox.showwarning("Input Error", "Please enter a valid port number.")
        return
    loading_popup = create_loading_popup("Checking Port Availability...")
    start_progress()
    availability = check_port_availability(port)
    stop_progress()
    loading_popup.destroy()  # Close the loading pop-up
    if availability:
        messagebox.showinfo("Port Availability", f"Port {port} is available.")
    else:
        messagebox.showinfo("Port Availability", f"Port {port} is in use.")

# Initialize the main tkinter window
window = tk.Tk()
window.title("IP and Port Scanner")
window.geometry("650x650")
window.resizable(False, False)

# Set the window icon (optional)
window.iconbitmap('ip-port-scanner.ico')

# Add a header label
header_label = ttk.Label(window, text="IP and Port Scanner", font=("Helvetica", 16))
header_label.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

# Create frames to organize the layout
ip_frame = ttk.LabelFrame(window, text="IP Scanning & Availability", padding=(10, 5))
ip_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

port_frame = ttk.LabelFrame(window, text="Port Scanning & Availability", padding=(10, 5))
port_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

result_frame = ttk.LabelFrame(window, text="Results", padding=(10, 5))
result_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

# Create and place the "Scan IPs" and "Scan Ports" buttons
scan_button = ttk.Button(ip_frame, text="Scan Active IPs", command=start_ip_scan)
scan_button.grid(row=0, column=0, padx=10, pady=10)

port_button = ttk.Button(port_frame, text="Scan Active Ports", command=start_port_scan)
port_button.grid(row=0, column=0, padx=10, pady=10)

# IP Availability Checker
ip_label = ttk.Label(ip_frame, text="Enter IP:")
ip_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
ip_entry = ttk.Entry(ip_frame)
ip_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
ip_check_button = ttk.Button(ip_frame, text="Check IP Availability", command=check_ip)
ip_check_button.grid(row=1, column=2, padx=10, pady=10)

# Port Availability Checker
port_label = ttk.Label(port_frame, text="Enter Port:")
port_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
port_entry = ttk.Entry(port_frame)
port_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
port_check_button = ttk.Button(port_frame, text="Check Port Availability", command=check_port)
port_check_button.grid(row=1, column=2, padx=10, pady=10)

# Create and place a scrolled text box to display scan results
result_header = ttk.Label(result_frame, text="Scan Results:", font=("Helvetica", 14))
result_header.grid(row=0, column=0, padx=10, pady=(5, 0), sticky="w")

result_box = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, width=70, height=10)
result_box.grid(row=1, column=0, padx=10, pady=10)
result_box.config(state=tk.DISABLED)

# Progress Bar
progress_bar = ttk.Progressbar(window, mode="indeterminate")
progress_bar.grid(row=5, column=0, columnspan=2, padx=10, pady=10)
progress_bar.grid_remove()

# Configure column weights for responsiveness
window.columnconfigure(0, weight=1)
window.columnconfigure(1, weight=1)
ip_frame.columnconfigure(1, weight=1)
port_frame.columnconfigure(1, weight=1)

# Start the tkinter main loop
window.mainloop()
