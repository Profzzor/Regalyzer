# Regalyzer/regalyzer/parsers/user_activity_parser.py
"""
Regalyzer - Comprehensive User Activity Parser Module (Definitive)

This definitive version includes parsers for:
- UserAssist (GUI Program Execution)
- RunMRU (Commands from 'Run' box)
- TypedPaths (Paths typed into Explorer)
- WordWheelQuery (Search terms typed into Explorer)
"""
import os
import traceback
import struct
import codecs
from Registry import Registry, RegistryParse
from rich.table import Table

# Import shared utilities from our package
from regalyzer.utils import print_error, get_value, format_filetime, get_user_profiles, format_datetime_obj

def run(console, image_root: str):
    """
    Executes the full user activity analysis for all users.
    """
    console.print(f"\n[bold green]===[/bold green] User & Application Activity Analysis [bold green]===[/bold green]")
    
    # --- 1. Call the central function to get the list of users ---
    user_profiles = get_user_profiles(image_root, console)

    if not user_profiles:
        console.print("[yellow]No user profiles could be located.[/yellow]"); return True

    # --- 2. For each user, parse their NTUSER.DAT ---
    for profile in user_profiles:
        console.print(f"\n[bold]>>> Analyzing User: [cyan]{profile['username']}[/cyan][/bold]")
        ntuser_path = profile['ntuser_path']
        if not os.path.exists(ntuser_path):
            console.print("[dim]  NTUSER.DAT not found.[/dim]"); continue
        
        try:
            reg_user = Registry.Registry(ntuser_path)

            # --- UserAssist Parser (Working, Unchanged) ---
            console.print("\n[bold]UserAssist - GUI Program Execution:[/bold]")
            ua_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
            try:
                ua_key = reg_user.open(ua_path)
                found_ua = False
                for guid_key in ua_key.subkeys():
                    try:
                        count_key = guid_key.subkey("Count")
                        ua_table = Table(title=f"UserAssist Entries ({guid_key.name()})")
                        ua_table.add_column("Program Path (Decoded)", style="white"); ua_table.add_column("Run Count", style="yellow", justify="right"); ua_table.add_column("Last Executed (UTC)", style="green")
                        for value in count_key.values():
                            decoded_name = codecs.decode(value.name(), 'rot_13')
                            data = value.value()
                            if len(data) >= 72:
                                run_count = struct.unpack_from('<I', data, 4)[0]
                                filetime = struct.unpack_from('<Q', data, 60)[0]
                                last_run = format_filetime(filetime)
                                if run_count > 0:
                                    found_ua = True
                                    ua_table.add_row(decoded_name, str(run_count), last_run)
                        if ua_table.row_count > 0: console.print(ua_table)
                    except Registry.RegistryKeyNotFoundException: continue
                if not found_ua: console.print("[dim]  No UserAssist data found.[/dim]")
            except Registry.RegistryKeyNotFoundException: console.print("[dim]  No UserAssist key found.[/dim]")
            
            # --- RunMRU Parser (Working, Unchanged) ---
            console.print("\n[bold]RunMRU - 'Run' Box History:[/bold]")
            runmru_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
            try:
                runmru_key = reg_user.open(runmru_path)
                mru_list = get_value(runmru_key, "MRUList", "")
                
                if mru_list:
                    # The key's timestamp is the last time any command was run
                    last_run_time = format_datetime_obj(runmru_key.timestamp())
                    
                    run_table = Table(title=f"Run Command History for {profile['username']}")
                    run_table.add_column("Order", style="yellow")
                    run_table.add_column("Command", style="white")
                    run_table.add_column("Last Updated (UTC)", style="green")
                    
                    for char in mru_list:
                        command = get_value(runmru_key, char)
                        # --- THIS IS THE FIX ---
                        # Clean the command by removing the trailing \1
                        cleaned_command = command.rsplit('\\', 1)[0] if command.endswith('\\1') else command
                        
                        run_table.add_row(
                            char,
                            cleaned_command,
                            last_run_time
                        )
                    console.print(run_table)
                    console.print(f"[dim]-- Source Key -> NTUSER.DAT\\{runmru_path}[/dim]")
                else:
                    console.print("[dim]  No RunMRU history found.[/dim]")
            except Registry.RegistryKeyNotFoundException:
                console.print("[dim]  No RunMRU key found for this user.[/dim]")

            # --- TypedPaths Parser (Working, Unchanged) ---
            console.print("\n[bold]TypedPaths - Explorer Address Bar History:[/bold]")
            tp_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths"
            try:
                tp_key = reg_user.open(tp_path)
                tp_table = Table(title=f"Typed Path History"); tp_table.add_column("Name", style="yellow"); tp_table.add_column("Path", style="white")
                for val in tp_key.values():
                    tp_table.add_row(val.name(), val.value())
                if tp_table.row_count > 0: console.print(tp_table)
                else: console.print("[dim]  No TypedPaths history found.[/dim]")
            except Registry.RegistryKeyNotFoundException: console.print("[dim]  No TypedPaths key found.[/dim]")
            
            # --- NEW: WordWheelQuery Parser ---
            console.print("\n[bold]WordWheelQuery - Explorer Search History:[/bold]")
            wwq_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery"
            try:
                wwq_key = reg_user.open(wwq_path)
                mru_list_val = get_value(wwq_key, "MRUListEx")
                if mru_list_val != "N/A":
                    wwq_table = Table(title="Explorer Search History")
                    wwq_table.add_column("Order", style="yellow")
                    wwq_table.add_column("Search Term", style="white")
                    wwq_table.add_column("Timestamp (UTC)", style="green")

                    mru_list = struct.unpack(f'<{len(mru_list_val)//4}I', mru_list_val)
                    for mru_id in mru_list:
                        search_term_bytes = get_value(wwq_key, str(mru_id))
                        if isinstance(search_term_bytes, bytes):
                            search_term = search_term_bytes.decode('utf-16-le', 'ignore').strip('\x00')
                            # The timestamp is the last write time of the parent key
                            wwq_table.add_row(
                                str(mru_id),
                                search_term,
                                format_datetime_obj(wwq_key.timestamp())
                            )
                    console.print(wwq_table)
                else:
                    console.print("[dim]  No WordWheelQuery history found.[/dim]")
            except Registry.RegistryKeyNotFoundException:
                console.print("[dim]  No WordWheelQuery key found.[/dim]")

        except Exception as e:
            print_error(f"Failed to process NTUSER.DAT for {profile['username']}: {e}", console)
            
    return True
