import subprocess
import re
import tkinter as tk
import platform

def get_connected_devices():
    try:
        # Run the command to list connected devices using subprocess
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        output = result.stdout

        # Use regex to extract IP, MAC addresses, and device names
        pattern = r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?P<mac>([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))\s+(?P<device>\S+)'
        devices = re.findall(pattern, output)

        # Return a list of tuples (IP, MAC, Device) of connected devices
        return devices
    except Exception as e:
        print(f"Error: {e}")
        return []

def disconnect_device(mac_address, button):
    try:
        # Run the command to block a specific device using subprocess
        subprocess.run(['arp', '-d', mac_address])
        button.config(state=tk.DISABLED, text="Disconnected", bg="red")
    except Exception as e:
        print(f"Error disconnecting device: {e}")

def get_wifi_name():
    try:
        if platform.system() == 'Windows':
            # For Windows, use netsh wlan command to get WiFi SSID
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True)
            output = result.stdout
            pattern = r'SSID\s+:\s+(?P<ssid>.+)'
            match = re.search(pattern, output)
            if match:
                return match.group('ssid').strip()
            else:
                return "Unknown"
        elif platform.system() in ['Linux', 'Darwin']:
            # For Linux and macOS, use iwconfig command to get WiFi SSID
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            output = result.stdout
            pattern = r'ESSID:"(?P<ssid>.*)"'
            match = re.search(pattern, output)
            if match:
                return match.group('ssid').strip()
            else:
                return "Unknown"
        else:
            return "Unknown"
    except Exception as e:
        print(f"Error getting WiFi name: {e}")
        return "Unknown"

def create_device_widgets(root, devices):
    wifi_name = get_wifi_name()
    wifi_label = tk.Label(root, text=f"Connected to WiFi: {wifi_name}", font=("Arial", 12, "bold"), fg="blue")
    wifi_label.pack(pady=10)

    for device in devices:
        frame = tk.Frame(root, bd=2, relief=tk.RIDGE, padx=10, pady=5)
        frame.pack(pady=5, fill=tk.X)

        label = tk.Label(frame, text=f"Device Name: {device[2]}", font=("Arial", 12, "bold"), fg="green")
        label.pack(side=tk.LEFT)

        ip_label = tk.Label(frame, text=f"IP: {device[0]}", font=("Arial", 10))
        ip_label.pack(side=tk.LEFT, padx=10)

        mac_label = tk.Label(frame, text=f"MAC: {device[1]}", font=("Arial", 10))
        mac_label.pack(side=tk.LEFT)

        disconnect_button = tk.Button(frame, text="Disconnect", bg="orange", fg="white", font=("Arial", 10, "bold"))
        disconnect_button.config(command=lambda mac=device[1], button=disconnect_button: disconnect_device(mac, button))
        disconnect_button.pack(side=tk.RIGHT)

if __name__ == "__main__":
    devices = get_connected_devices()

    if devices:
        root = tk.Tk()
        root.title("WiFi Device Manager")
        root.geometry("800x600")
        root.configure(bg="white")

        create_device_widgets(root, devices)

        root.mainloop()
    else:
        print("No devices connected.")