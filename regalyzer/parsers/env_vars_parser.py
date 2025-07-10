# Regalyzer/regalyzer/parsers/env_vars_parser.py

"""
Regalyzer - Environment Variables Parser Module
"""
import os
import traceback
from Registry import Registry, RegistryParse
from rich.table import Table

# Import shared utilities from our package
from regalyzer.utils import print_error, get_value

def run(console, image_root: str):
    """
    Executes the full environment variable analysis for the system and all users.
    """
    console.print(f"\n[bold green]===[/bold green] Environment Variable Analysis [bold green]===[/bold green]")
    
    system_path = os.path.join(image_root, 'Windows', 'System32', 'config', 'SYSTEM')
    software_path = os.path.join(image_root, 'Windows', 'System32', 'config', 'SOFTWARE')

    if not os.path.exists(system_path):
        print_error("Required SYSTEM hive not found for this module."); return False
    if not os.path.exists(software_path):
        print_error("Required SOFTWARE hive not found for this module."); return False
        
    try:
        reg_system = Registry.Registry(system_path)
        reg_software = Registry.Registry(software_path)
        
        # --- System-Wide Environment Variables ---
        console.print("\n[bold]System-Wide Environment Variables:[/bold]")
        select_key = reg_system.open("Select")
        cs_num = get_value(select_key, "Current")
        if cs_num == "N/A": raise ValueError("Could not determine CurrentControlSet.")

        env_path = f"ControlSet{cs_num:03d}\\Control\\Session Manager\\Environment"
        try:
            env_key = reg_system.open(env_path)
            system_vars_table = Table(title="System Variables")
            system_vars_table.add_column("Variable", style="cyan", no_wrap=True)
            system_vars_table.add_column("Value", style="white", overflow="fold")
            for value in env_key.values():
                system_vars_table.add_row(value.name(), str(value.value()))
            console.print(system_vars_table)
            console.print(f"\n[dim]-- Source Registry Key -> SYSTEM\\{env_path}[/dim]")
        except Registry.RegistryKeyNotFoundException:
            console.print(f"[dim]  System environment variables key not found.[/dim]")

        # --- Per-User Environment Variables ---
        console.print(f"\n[bold]Per-User Environment Variables:[/bold]")
        profile_list_key = reg_software.open("Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
        
        for sid_key in profile_list_key.subkeys():
            profile_path_raw = get_value(sid_key, "ProfileImagePath", "")
            if not profile_path_raw: continue
            expanded_path = os.path.expandvars(profile_path_raw)
            drive, path_no_drive = os.path.splitdrive(expanded_path)
            final_profile_path = os.path.join(image_root, path_no_drive.strip(os.sep))
            username = os.path.basename(final_profile_path)
            ntuser_path = os.path.join(final_profile_path, "NTUSER.DAT")

            if not os.path.exists(ntuser_path): continue

            console.print(f"\n[bold]>>> Analyzing User: [cyan]{username}[/cyan][/bold]")
            
            try:
                reg_user = Registry.Registry(ntuser_path)
                user_env_key_path = "Environment"
                user_env_key = reg_user.open(user_env_key_path)

                if len(user_env_key.values()) > 0:
                    user_vars_table = Table(title=f"User Variables for {username}", show_header=False)
                    user_vars_table.add_column("Variable", style="cyan", justify="right", no_wrap=True)
                    user_vars_table.add_column("Value", style="white", overflow="fold")
                    for value in user_env_key.values():
                        user_vars_table.add_row(f"{value.name()}:", str(value.value()))
                    console.print(user_vars_table)
                else:
                    console.print("[dim]  No specific environment variables set for this user.[/dim]")
            except Registry.RegistryKeyNotFoundException:
                console.print("[dim]  No 'Environment' key found for this user.[/dim]")
        return True

    except Exception as e:
        print_error(f"An unexpected error occurred in the Environment Variable parser: {e}")
        traceback.print_exc()
        return False
