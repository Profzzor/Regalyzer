# Create new file: Regalyzer/regalyzer/parsers/network_info_parser.py

"""
Regalyzer - Network Information Parser Module
"""
import os
import traceback
import ipaddress
from Registry import Registry
from rich.table import Table

# Import shared utilities from our package
from regalyzer.utils import print_error, get_value, format_timestamp, clean_multi_sz

def run(console, image_root: str):
    """
    Executes the network information analysis if the required hives are found.
    """
    system_path = os.path.join(image_root, 'Windows', 'System32', 'config', 'SYSTEM')
    if not os.path.exists(system_path):
        return False

    console.print(f"\n[bold green]===[/bold green] Network Configuration Analysis [bold green]===[/bold green]")
    
    try:
        reg_system = Registry.Registry(system_path)
        select_key = reg_system.open("Select")
        cs_num = get_value(select_key, "Current")
        if cs_num == "N/A": raise ValueError("Could not determine CurrentControlSet.")

        # --- Global TCP/IP Parameters ---
        params_path = f"ControlSet{cs_num:03d}\\Services\\Tcpip\\Parameters"
        params_key = reg_system.open(params_path)
        global_table = Table(title="Global TCP/IP Parameters", show_header=False, box=None, padding=(0, 2))
        global_table.add_column(style="cyan", justify="right"); global_table.add_column(style="white")
        global_table.add_row("Hostname:", get_value(params_key, "Hostname"))
        global_table.add_row("Domain:", get_value(params_key, "Domain"))
        console.print(global_table)
        
        # --- Interface Parsing ---
        class_path = f"ControlSet{cs_num:03d}\\Control\\Class\\{{4d36e972-e325-11ce-bfc1-08002be10318}}"
        interfaces4_path = f"ControlSet{cs_num:03d}\\Services\\Tcpip\\Parameters\\Interfaces"
        interfaces6_path = f"ControlSet{cs_num:03d}\\Services\\Tcpip6\\Parameters\\Interfaces"
        class_key = reg_system.open(class_path)
        
        active_interfaces = []
        inactive_interfaces = []

        for subkey in class_key.subkeys():
            guid = get_value(subkey, "NetCfgInstanceId")
            if guid == "N/A": continue
            
            description = get_value(subkey, "DriverDesc", "Unknown Interface")
            ipv4_info = {}; ipv6_info = {}
            
            try:
                iface4_key = reg_system.open(f"{interfaces4_path}\\{guid}")
                dhcp = get_value(iface4_key, "EnableDHCP") == 1
                ipv4_info = {
                    "dhcp": dhcp, "ip": clean_multi_sz(get_value(iface4_key, "DhcpIPAddress" if dhcp else "IPAddress", default=[])),
                    "subnet": clean_multi_sz(get_value(iface4_key, "DhcpSubnetMask" if dhcp else "SubnetMask", default=[])),
                    "gateway": clean_multi_sz(get_value(iface4_key, "DhcpDefaultGateway" if dhcp else "DefaultGateway", default=[])),
                    "dns": clean_multi_sz(get_value(iface4_key, "DhcpNameServer" if dhcp else "NameServer", default=[])),
                    "lease_obt": format_timestamp(get_value(iface4_key, "LeaseObtainedTime")),
                    "lease_exp": format_timestamp(get_value(iface4_key, "LeaseTerminatesTime")),
                }
            except Registry.RegistryKeyNotFoundException: pass

            try:
                iface6_key = reg_system.open(f"{interfaces6_path}\\{guid}")
                all_ipv6_addrs = []
                str_ips = clean_multi_sz(get_value(iface6_key, "IPAddress", default=[]))
                all_ipv6_addrs.extend(str_ips)
                binary_ips = get_value(iface6_key, "IPAddress", default=b'')
                if isinstance(binary_ips, bytes) and len(binary_ips) >= 16:
                    for i in range(0, len(binary_ips), 16):
                        chunk = binary_ips[i:i+16]
                        if len(chunk) == 16:
                            try: all_ipv6_addrs.append(str(ipaddress.IPv6Address(chunk)))
                            except ipaddress.AddressValueError: pass
                ipv6_info['ip'] = list(set(all_ipv6_addrs))
                ipv6_info['gateway'] = clean_multi_sz(get_value(iface6_key, "Dhcpv6DefaultGateway", default=[]))
            except Registry.RegistryKeyNotFoundException: pass

            if ipv4_info.get('ip') or ipv6_info.get('ip'):
                active_interfaces.append({"desc": description, "ipv4": ipv4_info, "ipv6": ipv6_info})
            else:
                inactive_interfaces.append({"desc": description, "guid": guid})

        console.print(f"\n[bold]Active Network Interfaces:[/bold]")
        if active_interfaces:
            active_table = Table(title="Interface Details", show_lines=True)
            active_table.add_column("Interface", style="cyan", max_width=35); active_table.add_column("IPv4 Info", style="white"); active_table.add_column("IPv6 Info", style="green")
            for iface in active_interfaces:
                ipv4_text = []
                if iface.get('ipv4', {}).get('ip'):
                    ipv4 = iface['ipv4']
                    ipv4_text.append(f"[bold]{'DHCP' if ipv4.get('dhcp') else 'Static'}[/bold]")
                    ipv4_text.append(f"IP: [yellow]{', '.join(ipv4['ip'])}[/yellow]")
                    ipv4_text.append(f"Subnet: [yellow]{', '.join(ipv4['subnet'])}[/yellow]")
                    ipv4_text.append(f"Gateway: [green]{', '.join(ipv4['gateway']) or 'N/A'}[/green]")
                    ipv4_text.append(f"DNS: [yellow]{', '.join(ipv4['dns']) or 'N/A'}[/yellow]")
                    if ipv4.get('dhcp') and ipv4['lease_obt'] != 'N/A':
                        ipv4_text.append(f"[dim]Lease: {ipv4['lease_obt']} -> {ipv4['lease_exp']}[/dim]")
                ipv6_text = []
                if iface.get('ipv6', {}).get('ip'):
                    ipv6 = iface['ipv6']
                    ipv6_text.append(f"IP: {', '.join(ipv6['ip'])}")
                    ipv6_text.append(f"Gateway: {', '.join(ipv6['gateway']) or 'N/A'}")
                active_table.add_row(iface['desc'], '\n'.join(ipv4_text) or "N/A", '\n'.join(ipv6_text) or "N/A")
            console.print(active_table)
        
        if inactive_interfaces:
            console.print(f"\n[bold]Other Detected Interfaces (no IP configuration):[/bold]")
            inactive_table = Table(title="Other Adapters")
            inactive_table.add_column("Description", style="dim"); inactive_table.add_column("GUID", style="dim")
            for iface in inactive_interfaces:
                inactive_table.add_row(iface['desc'], iface['guid'])
            console.print(inactive_table)
        
        console.print("\n[dim]-- Source Registry Keys --[/dim]")
        console.print(f"[dim]  -> SYSTEM\\{params_path}[/dim]")
        console.print(f"[dim]  -> SYSTEM\\{class_path}[/dim]")
        console.print(f"[dim]  -> SYSTEM\\{interfaces4_path}[/dim]")
        console.print(f"[dim]  -> SYSTEM\\{interfaces6_path}[/dim]")
        return True

    except Exception as e:
        print_error(f"Could not parse Network Configuration: {e}")
        traceback.print_exc()
        return False
