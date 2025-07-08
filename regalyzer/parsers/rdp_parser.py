# Create new file: Regalyzer/regalyzer/parsers/rdp_parser.py

"""
Regalyzer - RDP Usage Forensic Extractor
"""
import os
import traceback
from Registry import Registry, RegistryParse
from rich.table import Table

# Import shared utilities from our package
from regalyzer.utils import print_error, get_value, format_datetime_obj

def run(console, image_root: str):
    """
    Executes the full RDP usage analysis by finding and parsing
    all available user NTUSER.DAT hives.
    """
    console.print(f"\n[bold green]===[/bold green] RDP Usage Analysis [bold green]===[/bold green]")
    
    # --- 1. Find User Profiles from the SOFTWARE hive ---
    software_path = os.path.join(image_root, 'Windows', 'System32', 'config', 'SOFTWARE')
    if not os.path.exists(software_path):
        print_error("Required SOFTWARE hive not found for RDP analysis.")
        return False

    user_profiles = []
    try:
        reg_software = Registry.Registry(software_path)
        profile_list_path = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
        profile_list_key = reg_software.open(profile_list_path)
        
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
        print_error(f"Could not parse user profiles from SOFTWARE hive: {e}")
        traceback.print_exc()
        return False

    if not user_profiles:
        console.print("[yellow]No user profiles with NTUSER.DAT hives could be located and verified.[/yellow]")
        return True # Return True because the module ran, it just found nothing.
        
    console.print(f"Found [bold]{len(user_profiles)}[/bold] user profiles to analyze for RDP artifacts.\n")

    # --- 2. For each user, parse their hive ---
    for profile in user_profiles:
        console.print(f"[bold]>>> Analyzing User: [cyan]{profile['username']}[/cyan] (SID: {profile['sid']})[/bold]")
        console.print(f"[dim]    -> Hive: {profile['ntuser_path']}[/dim]")
        
        try:
            reg_user = Registry.Registry(profile['ntuser_path'])
            
            # --- RDP Server History (Outbound Connections) ---
            rdp_servers_table = Table(title=f"Outbound RDP History for {profile['username']}")
            rdp_servers_table.add_column("Server Address", style="yellow"); rdp_servers_table.add_column("Username Hint", style="yellow"); rdp_servers_table.add_column("Last Updated", style="green")
            
            servers_key_path = "Software\\Microsoft\\Terminal Server Client\\Servers"
            has_rdp_history = False
            try:
                servers_key = reg_user.open(servers_key_path)
                for server in servers_key.subkeys():
                    has_rdp_history = True
                    rdp_servers_table.add_row(server.name(), get_value(server, "UsernameHint"), format_datetime_obj(server.timestamp()))
            except Registry.RegistryKeyNotFoundException: pass

            if has_rdp_history:
                console.print(rdp_servers_table)
                console.print(f"[dim]-- Source Key -> NTUSER.DAT\\{servers_key_path}[/dim]")
            else:
                console.print("[dim]  No outbound RDP connection history found.[/dim]")

            # --- RDP Cache Evidence (Inbound Connections) ---
            console.print(f"\n[bold]Inbound RDP Cache Evidence:[/bold]")
            cache_path_relative = os.path.join("AppData", "Local", "Microsoft", "Terminal Server Client", "Cache")
            full_cache_path = os.path.join(os.path.dirname(profile['ntuser_path']), cache_path_relative)
            
            try:
                if os.path.isdir(full_cache_path) and any(f.endswith('.bin') for f in os.listdir(full_cache_path)):
                    console.print(f"[green]  [+] Found evidence:[/green] RDP bitmap cache files exist.")
                    console.print(f"[dim]     -> Location: {full_cache_path}[/dim]")
                else:
                    console.print("[dim]  No RDP client cache files found.[/dim]")
            except FileNotFoundError:
                console.print("[dim]  No RDP client cache files found.[/dim]")
            
            console.print("-" * 80)

        except Exception as e:
            print_error(f"Failed to process NTUSER.DAT for {profile['username']}: {e}")
            continue
            
    return True
