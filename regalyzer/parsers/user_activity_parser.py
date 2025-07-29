# Regalyzer/regalyzer/parsers/user_activity_parser.py
"""
Regalyzer - Comprehensive User Activity Parser Module
"""
import os
import traceback
import struct
import codecs
from Registry import Registry, RegistryParse
from rich.table import Table

# Import shared utilities from our package
from regalyzer.utils import print_error, get_value, format_filetime, parse_shell_item_path, get_user_profiles

def run(console, image_root: str):
    """
    Executes the full user activity analysis for all users.
    """
    console.print(f"\n[bold green]===[/bold green] User & Application Activity Analysis [bold green]===[/bold green]")
    
    # --- 1. Find User Profiles ---
    software_path = os.path.join(image_root, 'Windows', 'System32', 'config', 'SOFTWARE')
    if not os.path.exists(software_path):
        print_error("Required SOFTWARE hive not found for this module."); return False
    
    user_profiles = []
    try:
        reg_software = Registry.Registry(software_path)
        profile_list_key = reg_software.open("Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
        for sid_key in profile_list_key.subkeys():
            profile_path_raw = get_value(sid_key, "ProfileImagePath", "")
            if not profile_path_raw: continue
            expanded_path = os.path.expandvars(profile_path_raw)
            drive, path_no_drive = os.path.splitdrive(expanded_path)
            final_profile_path = os.path.join(image_root, path_no_drive.strip(os.sep))
            username = os.path.basename(final_profile_path)
            ntuser_path = os.path.join(final_profile_path, "NTUSER.DAT")
            if os.path.exists(ntuser_path):
                user_profiles.append({"username": username, "sid": sid_key.name(), "ntuser_path": ntuser_path})
    except Exception as e:
        print_error(f"Could not parse user profiles from SOFTWARE hive: {e}"); return False
    
    user_profiles = get_user_profiles(image_root, console)

    if not user_profiles:
        console.print("[yellow]No user profiles could be located.[/yellow]"); return True

    # --- 2. For each user, parse their NTUSER.DAT ---
    for profile in user_profiles:
        console.print(f"\n[bold]>>> Analyzing User: [cyan]{profile['username']}[/cyan][/bold]")
        if not os.path.exists(profile['ntuser_path']):
            console.print("[dim]  NTUSER.DAT not found.[/dim]"); continue
        
        try:
            reg_user = Registry.Registry(profile['ntuser_path'])

            # --- UserAssist ---
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
                                if run_count > 0: # Only show programs that have been run
                                    found_ua = True
                                    ua_table.add_row(decoded_name, str(run_count), last_run)
                        if ua_table.row_count > 0: console.print(ua_table)
                    except Registry.RegistryKeyNotFoundException: continue
                if not found_ua: console.print("[dim]  No UserAssist data found.[/dim]")
            except Registry.RegistryKeyNotFoundException: console.print("[dim]  No UserAssist key found.[/dim]")
            
            # --- RunMRU ---
            console.print("\n[bold]RunMRU - 'Run' Box History:[/bold]")
            runmru_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
            try:
                runmru_key = reg_user.open(runmru_path)
                mru_list = get_value(runmru_key, "MRUList", "")
                if mru_list:
                    run_table = Table(title=f"Run Command History"); run_table.add_column("Order", style="yellow"); run_table.add_column("Command", style="white")
                    for char in mru_list:
                        run_table.add_row(char, get_value(runmru_key, char))
                    console.print(run_table)
                else: console.print("[dim]  No RunMRU history found.[/dim]")
            except Registry.RegistryKeyNotFoundException: console.print("[dim]  No RunMRU key found.[/dim]")

            # --- TypedPaths ---
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

        except Exception as e:
            print_error(f"Failed to process NTUSER.DAT for {profile['username']}: {e}")
            
    return True
