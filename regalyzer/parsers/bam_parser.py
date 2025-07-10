# Regalyzer/regalyzer/parsers/bam_parser.py

"""
Regalyzer - BAM (Background Activity Moderator) Parser Module
"""
import os
import traceback
import struct
from datetime import datetime, timezone, timedelta
from Registry import Registry, RegistryParse
from rich.table import Table

# Import shared utilities from our package
from regalyzer.utils import print_error, get_value, format_filetime

def run(console, image_root: str):
    """
    Executes the full BAM service analysis from the SYSTEM hive.
    """
    console.print(f"\n[bold green]===[/bold green] BAM Program Execution Analysis [bold green]===[/bold green]")
    
    system_path = os.path.join(image_root, 'Windows', 'System32', 'config', 'SYSTEM')
    if not os.path.exists(system_path):
        print_error("Required SYSTEM hive not found for this module.")
        return False
        
    try:
        reg_system = Registry.Registry(system_path)
        select_key = reg_system.open("Select")
        cs_num = get_value(select_key, "Current")
        if cs_num == "N/A": raise ValueError("Could not determine CurrentControlSet.")

        bam_path = f"ControlSet{cs_num:03d}\\Services\\bam\\State\\UserSettings"
        console.print(f"[*] Analyzing BAM key: [cyan]SYSTEM\\{bam_path}[/cyan]\n")
        
        try:
            bam_key = reg_system.open(bam_path)
        except Registry.RegistryKeyNotFoundException:
            console.print("[dim]  BAM UserSettings key not found. No BAM data to parse.[/dim]")
            return True

        for sid_key in bam_key.subkeys():
            sid = sid_key.name()
            console.print(f"[bold]>>> User: [cyan]{sid}[/cyan][/bold]")
            
            bam_table = Table(title=f"Program Execution for {sid}")
            bam_table.add_column("Last Executed (UTC)", style="green", justify="right")
            bam_table.add_column("Executable Path", style="white")

            has_entries = False
            for value in sid_key.values():
                if value.name() in ["Version", "SequenceNumber", "(default)"]: continue

                exec_path = value.name()
                binary_data = value.value()
                
                if isinstance(binary_data, bytes) and len(binary_data) >= 8:
                    has_entries = True
                    filetime = struct.unpack_from('<Q', binary_data, 0)[0]
                    exec_time = format_filetime(filetime)
                    bam_table.add_row(exec_time, exec_path)

            if has_entries:
                console.print(bam_table)
            else:
                console.print("[dim]  No execution entries found for this user.[/dim]")
            console.print("\n")
        
        return True

    except Exception as e:
        print_error(f"An unexpected error occurred in the BAM parser: {e}")
        traceback.print_exc()
        return False
