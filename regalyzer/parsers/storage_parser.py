# Regalyzer/regalyzer/parsers/storage_parser.py

"""
Regalyzer - Storage & USB Device Forensic Extractor (Definitive, Corrected)
"""
import os
import re
import traceback
from datetime import datetime
from Registry import Registry, RegistryParse
from rich.table import Table

# Import shared utilities from our package
from regalyzer.utils import print_error, get_value, format_datetime_obj, find_timestamp_value

def run(console, image_root: str):
    """
    Executes the full storage device analysis, including the corrected
    correlation logic for USB devices.
    """
    console.print(f"\n[bold green]===[/bold green] Storage & USB History Analysis [bold green]===[/bold green]")
    
    system_path = os.path.join(image_root, 'Windows', 'System32', 'config', 'SYSTEM')
    software_path = os.path.join(image_root, 'Windows', 'System32', 'config', 'SOFTWARE')
    
    if not os.path.exists(system_path) or not os.path.exists(software_path):
        print_error("Required SYSTEM or SOFTWARE hive not found for this module.")
        return False
        
    try:
        reg_system = Registry.Registry(system_path)
        reg_software = Registry.Registry(software_path)
        select_key = reg_system.open("Select")
        cs_num = get_value(select_key, "Current")
        if cs_num == "N/A": raise ValueError("Could not determine CurrentControlSet.")

        # === 1. Build a lookup map from Enum\USB for VID/PID correlation ===
        usb_info_map = {}
        usb_path = f"ControlSet{cs_num:03d}\\Enum\\USB"
        try:
            usb_key = reg_system.open(usb_path)
            for vid_pid_key in usb_key.subkeys():
                match = re.search(r'VID_([^&]+)&PID_([^&]+)', vid_pid_key.name())
                if not match: continue
                vid, pid = match.groups()
                for instance_key in vid_pid_key.subkeys():
                    hw_id_list = get_value(instance_key, "HardwareID", default=[])
                    if isinstance(hw_id_list, str): hw_id_list = [hw_id_list]
                    # The key for our map is the USB instance key's name (e.g., '5&...').
                    usb_info_map[instance_key.name()] = {
                        "vid": vid, "pid": pid,
                        "last_connected": format_datetime_obj(instance_key.timestamp()),
                        "hardware_id": ', '.join(filter(None, hw_id_list))
                    }
        except Registry.RegistryKeyNotFoundException: pass
        
        # === 2. Physical Disks ===
        console.print(f"\n[bold]Physical Disks:[/bold]")
        disks_path = f"ControlSet{cs_num:03d}\\Enum\\SCSI"
        try:
            disks_key = reg_system.open(disks_path)
            disks_table = Table(title="Enumerated Physical Disks")
            disks_table.add_column("Device Description", style="cyan"); disks_table.add_column("First Installed (UTC)", style="green")
            for device_class in disks_key.subkeys():
                for instance in device_class.subkeys():
                    disks_table.add_row(get_value(instance, "FriendlyName", device_class.name()), format_datetime_obj(instance.timestamp()))
            console.print(disks_table)
            console.print(f"\n[dim]-- Source Registry Key -> SYSTEM\\{disks_path}[/dim]")
        except Registry.RegistryKeyNotFoundException:
            console.print(f"[dim]  Physical disk key not found at {disks_path}.[/dim]")
        
        # === 3. USB Mass Storage Devices (USBSTOR) ===
        console.print(f"\n[bold]USB Storage Device History:[/bold]")
        usbstor_path = f"ControlSet{cs_num:03d}\\Enum\\USBSTOR"
        try:
            usbstor_key = reg_system.open(usbstor_path)
            usb_table = Table(title="Connected USB Storage Devices", show_lines=True)
            usb_table.add_column("Device Info", style="cyan", max_width=35)
            usb_table.add_column("IDs", style="yellow")
            usb_table.add_column("Timestamps (UTC)", style="white")

            for device_class in usbstor_key.subkeys():
                for serial_key in device_class.subkeys():
                    vid, pid, last_connected, hardware_id = "N/A", "N/A", "N/A", "N/A"
                    serial_number_full = serial_key.name()
                    serial_number_short = serial_number_full.split('&')[0]

                    # --- YOUR PROVEN CORRELATION LOGIC ---
                    for usb_serial, usb_data in usb_info_map.items():
                        if usb_serial.startswith(serial_number_short):
                            vid, pid = usb_data["vid"], usb_data["pid"]
                            last_connected = usb_data["last_connected"]
                            hardware_id = usb_data["hardware_id"]
                            break
                    
                    first_installed = format_datetime_obj(serial_key.timestamp())
                    last_removed_dt = find_timestamp_value(serial_key, "0067")
                    last_removed = format_datetime_obj(last_removed_dt)
                    
                    if last_connected == "N/A":
                        last_connected = first_installed

                    device_info_text = f"[bold]{get_value(serial_key, 'FriendlyName', 'N/A')}[/bold]"
                    serial_id_text = (
                        f"[bold]Serial:[/bold] {serial_number_short}\n"
                        f"[yellow]VID:PID:[/yellow] {vid}:{pid}\n"
                        f"[dim]HW ID:[/dim] [dim]{hardware_id}[/dim]"
                    )
                    timestamp_text = (
                        f"[green]First Installed:[/green] {first_installed}\n"
                        f"[green]Last Connected:[/green]  {last_connected}\n"
                        f"[red]Last Removed:[/red]    {last_removed}"
                    )
                    
                    usb_table.add_row(device_info_text, serial_id_text, timestamp_text)
            
            console.print(usb_table)
            console.print(f"\n[dim]-- Correlated from SYSTEM\\{usbstor_path} and SYSTEM\\{usb_path}[/dim]")
        except Registry.RegistryKeyNotFoundException:
            console.print(f"[dim]USBSTOR key not found.[/dim]")

        # === 4. Windows Portable Devices (WPD) ===
        console.print(f"\n[bold]Windows Portable Devices (MTP/PTP):[/bold]")
        wpd_path = "Microsoft\\Windows Portable Devices\\Devices"
        try:
            wpd_key = reg_software.open(wpd_path)
            wpd_table = Table(title="Connected Portable Devices (e.g., Phones, Cameras)")
            wpd_table.add_column("Friendly Name", style="cyan"); wpd_table.add_column("Manufacturer", style="yellow"); wpd_table.add_column("Last Connected (UTC)", style="green")
            for device in wpd_key.subkeys():
                wpd_table.add_row(
                    get_value(device, "FriendlyName"),
                    get_value(device, "Manufacturer"),
                    format_datetime_obj(device.timestamp())
                )
            console.print(wpd_table)
            console.print(f"\n[dim]-- Source Registry Key -> SOFTWARE\\{wpd_path}[/dim]")
        except Registry.RegistryKeyNotFoundException:
            console.print(f"[dim]  WPD key not found.[/dim]")

        return True

    except Exception as e:
        print_error(f"An unexpected error occurred in the Storage parser: {e}")
        traceback.print_exc()
        return False
