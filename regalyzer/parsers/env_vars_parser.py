# regalyzer/parsers/env_vars_parser.py (Definitive, Corrected)
"""
Regalyzer - Environment Variables Parser Module (Refactored)
"""
import os
import traceback
from Registry import Registry
from rich.table import Table

# Import shared utilities from our package
from regalyzer.utils import print_error, get_value, get_user_profiles

def run(console, image_root: str):
    """
    Executes the full environment variable analysis for the system and all users.
    """
    console.print(f"\n[bold green]===[/bold green] Environment Variable Analysis [bold green]===[/bold green]")
    system_path = os.path.join(image_root, 'Windows', 'System32', 'config', 'SYSTEM')
    if not os.path.exists(system_path):
        print_error("Required SYSTEM hive not found for this module.", console); return False
        
    try:
        reg_system = Registry.Registry(system_path)
        # System-Wide Variables
        console.print("\n[bold]System-Wide Environment Variables:[/bold]")
        cs_num = get_value(reg_system.open("Select"), "Current")
        env_path = f"ControlSet{cs_num:03d}\\Control\\Session Manager\\Environment"
        try:
            env_key = reg_system.open(env_path)
            sys_table = Table(title="System Variables")
            sys_table.add_column("Variable", style="cyan", no_wrap=True)
            sys_table.add_column("Value", style="white", overflow="fold")
            for value in env_key.values():
                sys_table.add_row(value.name(), str(value.value()))
            console.print(sys_table)
            console.print(f"\n[dim]-- Source Registry Key -> SYSTEM\\{env_path}[/dim]")
        except Registry.RegistryKeyNotFoundException:
            console.print(f"[dim]  System environment key not found.[/dim]")

        # Per-User Variables
        console.print(f"\n[bold]Per-User Environment Variables:[/bold]")
        user_profiles = get_user_profiles(image_root, console)
        if not user_profiles:
            console.print("[yellow]No user profiles found.[/yellow]")
            return True
        
        for profile in user_profiles:
            console.print(f"\n[bold]>>> Analyzing User: [cyan]{profile['username']}[/cyan][/bold]")
            ntuser_path = profile['ntuser_path']
            if not os.path.exists(ntuser_path):
                console.print("[dim]  NTUSER.DAT not found.[/dim]")
                continue
            
            try:
                reg_user = Registry.Registry(ntuser_path)
                user_env_key_path = "Environment"
                user_env_key = reg_user.open(user_env_key_path)

                if len(user_env_key.values()) > 0:
                    user_vars_table = Table(title=f"User Variables for {profile['username']}", show_header=False)
                    user_vars_table.add_column("Var", justify="right", style="cyan", no_wrap=True)
                    user_vars_table.add_column("Val", style="white", overflow="fold")
                    for value in user_env_key.values():
                        user_vars_table.add_row(f"{value.name()}:", str(value.value()))
                    console.print(user_vars_table)
                    console.print(f"[dim]-- Source Registry Key -> NTUSER.DAT\\{user_env_key_path}[/dim]")
                else:
                    console.print("[dim]  No specific environment variables set for this user.[/dim]")
            except Registry.RegistryKeyNotFoundException:
                console.print("[dim]  No 'Environment' key found for this user.[/dim]")
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}", console)
        traceback.print_exc()
    return True
