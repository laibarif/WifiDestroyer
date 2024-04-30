# import psutil
# import tkinter as tk
# from functools import partial
# from tkinter import messagebox
# from scapy.all import ARP, Ether, srp
# import socket
# import subprocess
# import re

# def get_connected_devices(network_range):
#     try:
#         # Print the IP address range
#         print("Scanning IP address range...")
#         print("Network range:", network_range)

#         # Send ARP request to the local network
#         arp_request = ARP(pdst=network_range)
#         ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
#         packet = ether / arp_request
#         result = srp(packet, timeout=3, verbose=False)[0]

#         # Extract IP, MAC addresses, and hostnames from the responses
#         devices = []
#         for response in result:
#             ip_address = response[1].psrc
#             mac_address = response[1].hwsrc
#             try:
#                 hostname = socket.gethostbyaddr(ip_address)[0]
#             except socket.herror:
#                 hostname = "Unknown"

#             # Exclude the gateway IP address from the list of devices
#             if ip_address != network_range.split('/')[0]:
#                 devices.append((hostname, ip_address, mac_address))

#         # Print out the result variable
#         print("ARP response result:", devices)

#         return devices
#     except Exception as e:
#         print(f"Error fetching devices with Scapy: {e}")
#         return []

# def get_wifi_network():
#     try:
#         result = subprocess.run(['ipconfig'], capture_output=True, text=True)
#         output = result.stdout
#         print("Output of ipconfig command:", output)  # Debug print

#         # Use regex to extract the IPv4 address of the WiFi network
#         ipv4_pattern = r'Wireless LAN adapter Wi-Fi:[\s\S]*?IPv4 Address[.\s]+:\s+([^\r\n]+)'
#         ipv4_match = re.search(ipv4_pattern, output)

#         if ipv4_match:
#             ipv4_address = ipv4_match.group(1)
#             return ipv4_address, None
#         else:
#             return None, "Failed to extract IPv4 address from ipconfig output"
#     except Exception as e:
#         print(f"Error getting WiFi network information: {e}")
#         return None, str(e)



# def get_wifi_interface_name():
#     try:
#         result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True)
#         output = result.stdout
#         pattern = r'^\s+Name\s+:\s+(?P<interface>.+)$'
#         match = re.search(pattern, output, re.MULTILINE)
#         if match:
#             return match.group('interface').strip()
#         else:
#             return None
#     except Exception as e:
#         print(f"Error getting WiFi interface name: {e}")
#         return None

# def show_devices(devices_label, connected_devices_frame, wifi_label):
#     # Get the connected WiFi network and its subnet mask
#     network_range, _ = get_wifi_network()
#     if network_range:
#         # Get the connected devices
#         devices = get_connected_devices(network_range)

#         if devices:
#             devices_label.config(text="Number of connected devices: {}".format(len(devices)))
#             connected_devices_frame.pack()

#             for widget in connected_devices_frame.winfo_children():
#                 widget.destroy()

#             for device in devices:
#                 device_name, ip_address, _ = device
#                 device_frame = tk.Frame(connected_devices_frame)
#                 device_frame.pack(pady=5)

#                 device_label = tk.Label(device_frame, text=f"Device Name: {device_name}, IP: {ip_address}")
#                 device_label.pack(side=tk.LEFT)

#                 disconnect_button = tk.Button(device_frame, text="Disconnect", bg="orange", fg="white")
#                 disconnect_button.pack(side=tk.RIGHT)

#                 # Create a lambda function with default arguments to pass the disconnect_button
#                 disconnect_button.config(command=lambda ip=ip_address, name=device_name, button=disconnect_button: block_wifi(ip, name, wifi_label, button))
#         else:
#             devices_label.config(text="No devices connected.")
#     else:
#         messagebox.showerror("Error", "Failed to get WiFi network information.")

# def block_wifi(ip_address, device_name, wifi_label, button):
#     try:
#         interface_name = get_wifi_interface_name()
#         if interface_name:
#             command = ['netsh', 'interface', 'set', 'interface', f'name="{interface_name}"', 'admin=disable']
#             result = subprocess.run(command, capture_output=True, text=True, check=True)
#             if result.returncode == 0:
#                 print(f"Disabled Wi-Fi for device with IP: {ip_address}")
#                 messagebox.showinfo("Wi-Fi Disabled", f"Wi-Fi disabled for device '{device_name}' with IP: {ip_address}")
#                 wifi_label.config(text="Wi-Fi Disabled")
#                 button.config(text="Disconnected", bg="red", state=tk.DISABLED)
#             else:
#                 print(f"Failed to disable Wi-Fi for device with IP: {ip_address}. Error: {result.stderr}")
#                 print("Command output:", result.stdout)
#                 messagebox.showerror("Error", f"Failed to disable Wi-Fi for device with IP: {ip_address}")
#         else:
#             print("Error: Wi-Fi interface not found.")
#             messagebox.showerror("Error", "Wi-Fi interface not found.")
#     except subprocess.CalledProcessError as e:
#         print(f"Error blocking Wi-Fi for device with IP {ip_address}: {e}")
#         print("Command output:", e.output)
#         messagebox.showerror("Error", f"Error blocking Wi-Fi for device with IP {ip_address}: {e}")

# def get_wifi_network_name():
#     try:
#         result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True)
#         output = result.stdout
#         pattern = r'SSID\s+:\s+(?P<ssid>.+)'
#         match = re.search(pattern, output)
#         if match:
#             return match.group('ssid').strip()
#         else:
#             return "Unknown"
#     except Exception as e:
#         print(f"Error getting WiFi network name: {e}")
#         return "Unknown"

# def main():
#     root = tk.Tk()
#     root.title("WiFi Device Monitor")
#     root.geometry("600x400")

#     wifi_name = get_wifi_network_name()
#     wifi_label = tk.Label(root, text=f"Connected to WiFi: {wifi_name}", font=("Arial", 14))
    
#     wifi_label.pack(pady=10)

#     devices_label = tk.Label(root, text="", font=("Arial", 12))
#     connected_devices_frame = tk.Frame(root)

#     fetch_button = tk.Button(root, text="Fetch Devices", font=("Arial", 14), bg="#2ECC71", fg="white",
#                              command=partial(show_devices, devices_label, connected_devices_frame, wifi_label))
#     fetch_button.pack(pady=10)

#     root.mainloop()

# if __name__ == "__main__":
#     main()

import tkinter as tk
from functools import partial
from tkinter import messagebox
from scapy.all import ARP, Ether, srp
import subprocess
import re

def get_connected_devices(network_range):
    try:
        print("Scanning IP address range...")
        print("Network range:", network_range)

        arp_request = ARP(pdst=network_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request
        result = srp(packet, timeout=3, verbose=False)[0]

        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        print("ARP response result:", devices)
        return devices
    except Exception as e:
        print(f"Error fetching devices with Scapy: {e}")
        return []

def get_wifi_network(ip_config_output):
    try:
        ipv4_pattern = r'Wireless LAN adapter Wi-Fi:[\s\S]*?IPv4 Address[.\s]+:\s+([^\r\n]+)'
        ipv4_match = re.search(ipv4_pattern, ip_config_output)

        if ipv4_match:
            ipv4_address = ipv4_match.group(1)
            network_range = f"{ipv4_address}/24"
            return network_range
        else:
            return None
    except Exception as e:
        print(f"Error getting WiFi network information: {e}")
        return None

def show_devices(devices_label, connected_devices_frame, wifi_label):
    try:
        result = subprocess.run(['ipconfig'], capture_output=True, text=True)
        ip_config_output = result.stdout

        network_range = get_wifi_network(ip_config_output)

        if network_range:
            devices = get_connected_devices(network_range)

            if devices:
                devices_label.config(text="Number of connected devices: {}".format(len(devices)))
                connected_devices_frame.pack()

                for widget in connected_devices_frame.winfo_children():
                    widget.destroy()

                for device in devices:
                    device_frame = tk.Frame(connected_devices_frame)
                    device_frame.pack(pady=5)

                    device_label = tk.Label(device_frame, text=f"Device: {device['mac']} ({device['ip']})")
                    device_label.pack(side=tk.LEFT)

                    disconnect_button = tk.Button(device_frame, text="Disconnect", bg="orange", fg="white")
                    disconnect_button.pack(side=tk.RIGHT)

                    disconnect_button.config(command=lambda ip=device['ip'], mac=device['mac'], button=disconnect_button: block_wifi(ip, mac, wifi_label, button))
            else:
                devices_label.config(text="No devices connected.")
        else:
            messagebox.showerror("Error", "Failed to get WiFi network information.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def block_wifi(ip_address, mac_address, wifi_label, button):
    try:
        interface_name = get_wifi_interface_name()
        if interface_name:
            command = ['netsh', 'interface', 'set', 'interface', f'name="{interface_name}"', 'admin=disable']
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            if result.returncode == 0:
                print(f"Disabled Wi-Fi for device with IP: {ip_address}")
                messagebox.showinfo("Wi-Fi Disabled", f"Wi-Fi disabled for device with IP: {ip_address}")
                wifi_label.config(text="Wi-Fi Disabled")
                button.config(text="Disconnected", bg="red", state=tk.DISABLED)
            else:
                print(f"Failed to disable Wi-Fi for device with IP: {ip_address}. Error: {result.stderr}")
                print("Command output:", result.stdout)
                messagebox.showerror("Error", f"Failed to disable Wi-Fi for device with IP: {ip_address}")
        else:
            print("Error: Wi-Fi interface not found.")
            messagebox.showerror("Error", "Wi-Fi interface not found.")
    except subprocess.CalledProcessError as e:
        print(f"Error blocking Wi-Fi for device with IP {ip_address}: {e}")
        print("Command output:", e.output)
        messagebox.showerror("Error", f"Error blocking Wi-Fi for device with IP {ip_address}: {e}")

def get_wifi_interface_name():
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True)
        output = result.stdout
        pattern = r'^\s+Name\s+:\s+(?P<interface>.+)$'
        match = re.search(pattern, output, re.MULTILINE)
        if match:
            return match.group('interface').strip()
        else:
            return None
    except Exception as e:
        print(f"Error getting WiFi interface name: {e}")
        return None

def get_wifi_network_name():
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True)
        output = result.stdout
        pattern = r'SSID\s+:\s+(?P<ssid>.+)'
        match = re.search(pattern, output)
        if match:
            return match.group('ssid').strip()
        else:
            return "Unknown"
    except Exception as e:
        print(f"Error getting WiFi network name: {e}")
        return "Unknown"

def main():
    root = tk.Tk()
    root.title("WiFi Device Monitor")
    root.geometry("600x400")

    wifi_name = get_wifi_network_name()
    wifi_label = tk.Label(root, text=f"Connected to WiFi: {wifi_name}", font=("Arial", 14))
    
    wifi_label.pack(pady=10)

    devices_label = tk.Label(root, text="", font=("Arial", 12))
    connected_devices_frame = tk.Frame(root)

    fetch_button = tk.Button(root, text="Fetch Devices", font=("Arial", 14), bg="#2ECC71", fg="white",
                             command=partial(show_devices, devices_label, connected_devices_frame, wifi_label))
    fetch_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
