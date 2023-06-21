import socket
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import subprocess
import nmap

def get_os_and_hostname(ip_address):
    nm = nmap.PortScanner()
    nm.scan(ip_address, arguments='-O')

    os_name = 'N/A'
    os_vendor = 'N/A'
    os_version = 'N/A'
    os_accuracy = 'N/A'
    hostname = 'N/A'

    if ip_address in nm.all_hosts() and 'osmatch' in nm[ip_address]:
        os_matches = nm[ip_address]['osmatch']
        for os_match in os_matches:
            os_name = os_match['name']
            os_accuracy = os_match['accuracy']

            if 'osclass' in os_match:
                os_classes = os_match['osclass']
                for os_class in os_classes:
                    os_vendor = os_class.get('vendor', 'Unknown Vendor')
                    os_version = os_class.get('osversion', 'Unknown Version')

    if ip_address in nm.all_hosts() and 'hostnames' in nm[ip_address]:
        hostnames = nm[ip_address]['hostnames']
        if len(hostnames) > 0:
            hostname = hostnames[0]['name']

    return os_name, os_vendor, os_version, os_accuracy, hostname





def get_local_ip():
    temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    temp_socket.connect(("8.8.8.8", 80))
    local_ip = temp_socket.getsockname()[0]
    temp_socket.close()
    return local_ip


def get_connected_devices(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-sn')
    devices = []
    for host in nm.all_hosts():
        device = {
            "ip": host,
            "mac": nm[host]['addresses'].get('mac', 'N/A'),
            "status": nm[host].state()}
        devices.append(device)
    return devices


def scan_network():
    ip_range = local_ip_entry.get() + "/24"
    devices = get_connected_devices(ip_range)

    device_listbox.delete(*device_listbox.get_children())

    for device in devices:
        ip = device["ip"]
        mac = device["mac"]
        status = device["status"]
        device_listbox.insert("", "end", text="*",
                              values=(mac,ip, status))



def get_device_info():
    selected_item = device_listbox.focus()
    if selected_item:
        item_values = device_listbox.item(selected_item)["values"]
        ip_address = str(item_values[1])  # Convert IP address to string
        os_name, os_vendor, os_version, os_accuracy, hostname = get_os_and_hostname(ip_address)
        info_text.delete(1.0, tk.END)
        info_text.insert(tk.END, f"IP Address: {ip_address}\n")
        info_text.insert(tk.END, f"MAC Address: {item_values[0]}\n")
        info_text.insert(tk.END, f"Status: {item_values[2]}\n")
        info_text.insert(tk.END, f"Hostname: {hostname}\n")
        info_text.insert(tk.END, f"Operating System: {os_name}\n")
        info_text.insert(tk.END, f"Vendor: {os_vendor}\n")
        info_text.insert(tk.END, f"Version: {os_version}\n")
        info_text.insert(tk.END, f"Accuracy: {os_accuracy}%\n")




def ping_device():
    selected_item = device_listbox.focus()
    if selected_item:
        item_values = device_listbox.item(selected_item)["values"]
        ip_address = item_values[1]
        if ip_address:
            try:
                output = subprocess.check_output(
                    ['ping', '-c', '4', ip_address])
                result_text = f"Ping to {ip_address} successful!"
                response_text.config(state=tk.NORMAL)  # Enable editing
                response_text.insert(
                    tk.END, result_text + "\n")  # Append result
                response_text.config(state=tk.DISABLED)  # Disable editing
                messagebox.showinfo("Ping Result", result_text)
            except subprocess.CalledProcessError:
                result_text = f"Ping to {ip_address} failed!"
                response_text.config(state=tk.NORMAL)  # Enable editing
                response_text.insert(
                    tk.END, result_text + "\n")  # Append result
                response_text.config(state=tk.DISABLED)  # Disable editing
                messagebox.showerror("Ping Result", result_text)
        else:
            messagebox.showerror(
                "Ping Error", "Please enter an IP address to ping.")


# Create the main window
window = tk.Tk()
window.title("Network Scanner")
window.geometry("600x800")

# Create the input frame
input_frame = tk.Frame(window)
input_frame.pack(pady=10)

# Create and position the local IP label and entry
local_ip_label = tk.Label(input_frame, text="Local IP:")
local_ip_label.grid(row=0, column=0, padx=5)
local_ip_entry = tk.Entry(input_frame, width=15)
local_ip_entry.insert(tk.END, get_local_ip())
local_ip_entry.grid(row=0, column=1, padx=5)

# Create and position the scan button
scan_button = tk.Button(input_frame, text="Scan Network", command=scan_network)
scan_button.grid(row=0, column=2, padx=5)

# Create the device treeview
# Create the device treeview
device_listbox = ttk.Treeview(
    window, columns=("mac", "ip", "status"))
device_listbox.heading("#0", text="S.N")
device_listbox.heading("mac", text="MAC Address")
device_listbox.heading("ip", text="IP Address")
device_listbox.heading("status", text="Status")
device_listbox.column("#0", width=50)
device_listbox.column("mac", width=180)
device_listbox.column("ip", width=180)
device_listbox.column("status", width=100)
device_listbox.pack(pady=10)


# Create the clear button
clear_button = tk.Button(window, text="Clear List", command=lambda: device_listbox.delete(
    *device_listbox.get_children()))
clear_button.pack(pady=5)


# Create the ping button
ping_button = tk.Button(window, text="Ping", command=ping_device)
ping_button.pack(pady=5)

# Create the ping text box
response_frame = tk.Frame(window)
response_frame.pack(pady=10)
response_label = tk.Label(response_frame, text="Ping Response:")
response_label.pack()
response_text = tk.Text(response_frame, width=60, height=5)
response_text.pack()
response_text.config(bg="black", fg="white")
response_text.config(state=tk.DISABLED)

# Create the information text box
info_text = tk.Text(window, width=60, height=10)
info_text.pack(pady=10)

#  info button
info_button = tk.Button(window, text="Get Device Info",
                        command=get_device_info)
info_button.pack(pady=5)


window.mainloop()
