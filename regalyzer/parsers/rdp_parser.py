# Regalyzer/regalyzer/parsers/rdp_parser.py (Definitive, Corrected)
"""
Regalyzer - RDP Usage Forensic Extractor (Refactored with Proven Logic)
"""
import os
import traceback
from Registry import Registry
from rich.table import Table

# Import the new central function and other utilities from our shared utils.py
from regalyzer.utils import print_error, get_value, get_user_profiles, format_datetime_obj

def run(console, image_root: str):
    """
    Executes the full RDP usage analysis by calling the centralized
    user profile discovery function and using the proven parsing logic.
    """
    console.print(f"\n[bold green]===[/bold green] RDP Usage Analysis [bold green]===[/bold green]")
    
    # --- Call the central function to get the list of users ---
    user_profiles = get_user_profiles(image_root, console)

    if not user_profiles:
        console.print("[yellow]No user profiles found for RDP analysis.[/yellow]")
        return True
        
    console.print(f"Found [bold]{len(user_profiles)}[/bold] user profiles to analyze for RDP artifacts.\n")

    # --- For each user, parse their hive using YOUR proven logic ---
    for profile in user_profiles:
        console.print(f"[bold]>>> Analyzing User: [cyan]{profile['username']}[/cyan] (SID: {profile['sid']})[/bold]")
        console.print(f"[dim]    -> Hive: {profile['ntuser_path']}[/dim]")
        
        ntuser_path = profile['ntuser_path']
        if not os.path.exists(ntuser_path):
            console.print("[dim]  NTUSER.DAT not found.[/dim]\n--------------------------------------------------------------------------------")
            continue
            
        try:
            reg_user = Registry.Registry(ntuser_path)
            
            # RDP Server History (Outbound Connections)
            servers_key_path = "Software\\Microsoft\\Terminal Server Client\\Servers"
            has_rdp_history = False
            try:
                servers_key = reg_user.open(servers_key_path)
                rdp_table = Table(title=f"Outbound RDP History for {profile['username']}")
                rdp_table.add_column("Server Address", style="white")
                rdp_table.add_column("Username Hint", style="yellow")
                rdp_table.add_column("Last Updated", style="green")

                for server in servers_key.subkeys():
                    has_rdp_history = True
                    rdp_table.add_row(
                        server.name(),
                        get_value(server, "UsernameHint"),
                        format_datetime_obj(server.timestamp())
                    )
                
                if has_rdp_history:
                    console.print(rdp_table)
                    console.print(f"[dim]-- Source Key -> NTUSER.DAT\\{servers_key_path}[/dim]")
                else:
                    console.print("[dim]  No outbound RDP connection history found.[/dim]")
                    
            except Registry.RegistryKeyNotFoundException:
                console.print("[dim]  No outbound RDP connection history found.[/dim]")

            # RDP Cache Evidence (Inbound Connections)
            console.print(f"\n[bold]Inbound RDP Cache Evidence:[/bold]")
            cache_path = os.path.join(profile['profile_path'], "AppData", "Local", "Microsoft", "Terminal Server Client", "Cache")
            try:
                if os.path.isdir(cache_path) and any(f.endswith('.bin') for f in os.listdir(cache_path)):
                    console.print(f"[green]  [+] Found evidence:[/green] RDP bitmap cache files exist.")
                    console.print(f"[dim]     -> Location: {cache_path}[/dim]")
                else:
                    console.print("[dim]  No RDP client cache files found.[/dim]")
            except FileNotFoundError:
                console.print("[dim]  No RDP client cache files found.[/dim]")

        except Exception as e:
            print_error(f"Failed to process NTUSER.DAT for {profile['username']}: {e}", console)
        finally:
            console.print("--------------------------------------------------------------------------------")
            
    return True
