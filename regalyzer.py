# Regalyzer/regalyzer.py

"""
Regalyzer - Python Registry Forensics Toolkit

Main entry point for the toolkit. This script automatically finds
and runs all available parsers on the target image directory.
"""
import os
import sys
import argparse
from rich.console import Console

# --- Import Parser Modules ---
# To add a new parser, simply import it here and add it to the PARSERS list.
from regalyzer.parsers import os_info_parser 
from regalyzer.parsers import network_info_parser
from regalyzer.parsers import storage_parser
from regalyzer.parsers import sam_parser
from regalyzer.parsers import rdp_parser

# --- List of all available parsers ---
# The order in this list determines the order of execution.
PARSERS = [
    ("System Information", os_info_parser),
    ("Network Configuration", network_info_parser),
    ("Storage & USB History", storage_parser),
    ("SAM User Accounts", sam_parser),
    ("RDP Usage", rdp_parser),
]

def main():
    """Main controller function."""
    console = Console()
    console.print("[bold blue]Regalyzer - Registry Forensics Toolkit v2.1[/bold blue]")

    parser = argparse.ArgumentParser(
        description="Automatically analyze registry hives from a forensic image.",
        epilog="Example: python regalyzer.py 'C:\\Users\\Profzzor\\Desktop\\latus\\C___NONAME [NTFS]\\[root]'"
    )
    parser.add_argument(
        'image_root', metavar='<image_root_dir>', type=str,
        help="Path to the root of the forensic image (e.g., 'C:\\' or '/mnt/c_drive')."
    )
    args = parser.parse_args()

    if not os.path.isdir(args.image_root):
        console.print(f"[bold red]Error:[/bold red] The specified directory does not exist: {args.image_root}")
        sys.exit(1)

    console.print(f"\n[+] Analyzing target: [cyan]{args.image_root}[/cyan]")
    
    parsers_run_count = 0
    for name, module in PARSERS:
        if module.run(console, args.image_root):
            parsers_run_count += 1
    
    console.print("\n" + "="*80)
    if parsers_run_count > 0:
        console.print(f"[bold green]Analysis complete. {parsers_run_count} parser(s) ran successfully.[/bold green]")
    else:
        console.print(f"[bold yellow]Analysis complete. No suitable registry hives were found for any available parsers.[/bold yellow]")
        console.print("[yellow]Please ensure the target directory is the root of a Windows filesystem (e.g., contains a 'Windows' folder).[/yellow]")

if __name__ == "__main__":
    main()
