# Regalyzer/regalyzer/parsers/os_info_parser.py

"""
Regalyzer - OS Information Parser Module
"""
import os
import traceback
import struct
from datetime import datetime, timezone

from Registry import Registry
from rich.table import Table

# Import shared utilities from our package
from regalyzer.utils import print_error, get_value

def run(console, image_root: str):
    """
    Executes the OS information analysis if the required hives are found.

    Args:
        console: A rich.console.Console object for printing.
        image_root: The path to the root of the forensic image.

    Returns:
        bool: True if the parser ran successfully, False otherwise.
    """
    config_path = os.path.join(image_root, 'Windows', 'System32', 'config')
    software_path = os.path.join(config_path, 'SOFTWARE')
    system_path = os.path.join(config_path, 'SYSTEM')

    if not os.path.exists(software_path) and not os.path.exists(system_path):
        return False

    console.print(f"\n[bold green]===[/bold green] System Information Analysis [bold green]===[/bold green]")
    
    try:
        os_info = {}
        # --- NEW: List to store the paths of the keys we use ---
        source_paths = []

        # 1. Parse SOFTWARE hive
        if os.path.exists(software_path):
            reg_software = Registry.Registry(software_path)
            key_path = "Microsoft\\Windows NT\\CurrentVersion"
            key = reg_software.open(key_path)
            
            # --- NEW: Add the successfully opened key path to our list ---
            source_paths.append(f"SOFTWARE\\{key_path}")

            os_info["Product Name"] = get_value(key, "ProductName")
            # ... (rest of SOFTWARE parsing is unchanged) ...
            os_info["Edition ID"] = get_value(key, "EditionID")
            os_info["Display Version"] = get_value(key, "DisplayVersion")
            build_num = get_value(key, "CurrentBuildNumber", "N/A")
            ubr = get_value(key, "UBR", "N/A")
            os_info["OS Build"] = f"{build_num}.{ubr}" if build_num != "N/A" else "Not Found"
            os_info["Build Lab"] = get_value(key, "BuildLabEx")
            os_info["System Root"] = get_value(key, "SystemRoot")
            os_info["Registered Owner"] = get_value(key, "RegisteredOwner")
            os_info["Registered Organization"] = get_value(key, "RegisteredOrganization")
            os_info["Product ID"] = get_value(key, "ProductId")
            install_timestamp = get_value(key, "InstallDate", 0)
            if install_timestamp > 0:
                os_info["Install Date"] = datetime.fromtimestamp(install_timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
            else:
                os_info["Install Date"] = "Not Found"
        
        # 2. Parse SYSTEM hive
        if os.path.exists(system_path):
            reg_system = Registry.Registry(system_path)
            select_key = reg_system.open("Select")
            current_control_set_num = get_value(select_key, "Current", 0)
            if current_control_set_num > 0:
                
                # Get Hostname
                computername_path = f"ControlSet{current_control_set_num:03d}\\Control\\ComputerName\\ComputerName"
                cn_key = reg_system.open(computername_path)
                os_info["Hostname"] = get_value(cn_key, "ComputerName")

                control_set_path = f"ControlSet{current_control_set_num:03d}\\Control\\TimeZoneInformation"
                tz_key = reg_system.open(control_set_path)
                
                # --- NEW: Add the dynamically found key path to our list ---
                source_paths.append(f"SYSTEM\\{control_set_path}")

                tz_name = get_value(tz_key, "TimeZoneKeyName")
                unsigned_bias = get_value(tz_key, "Bias", None)

                if unsigned_bias is not None and isinstance(unsigned_bias, int):
                    try:
                        packed_bias = struct.pack('<I', unsigned_bias)
                        signed_bias = struct.unpack('<i', packed_bias)[0]
                    except struct.error:
                        signed_bias = 0
                    
                    offset_minutes = -signed_bias
                    hours, rem_minutes = divmod(abs(offset_minutes), 60)
                    sign = '+' if offset_minutes >= 0 else '-'
                    offset_str = f"UTC{sign}{hours:02d}:{rem_minutes:02d}"
                    os_info["Time Zone"] = f"{tz_name} ({offset_str})"
                else:
                    os_info["Time Zone"] = tz_name

        # --- Display Results Table (Unchanged) ---
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column(style="cyan", justify="right")
        table.add_column(style="white")
        report_order = ["Product Name", "Edition ID", "Hostname", "Display Version", "OS Build", "Build Lab", # <<< ADD Hostname here
                        "Install Date", "System Root", "Registered Owner", "Registered Organization",
                        "Product ID", "Time Zone"]
        for key in report_order:
            value = os_info.get(key, "Not Found")
            table.add_row(f"{key}:", str(value))
        console.print(table)
        
        # ########################################################
        # ### START: NEW - PRINT SOURCE LOCATIONS ###
        # ########################################################
        if source_paths:
            console.print("\n[dim]-- Source Registry Keys --[/dim]")
            for path in source_paths:
                console.print(f"[dim]  -> {path}[/dim]")
        # ########################################################
        # ### END: NEW - PRINT SOURCE LOCATIONS ###
        # ########################################################

        return True

    except Exception as e:
        print_error(f"An unexpected error occurred in the OS Info parser: {e}")
        traceback.print_exc()
        return False
