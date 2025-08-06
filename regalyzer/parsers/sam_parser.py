# Regalyzer/regalyzer/parsers/sam_parser.py

"""
Regalyzer - SAM Hive Parser Module
"""
import os
import io
import struct
import contextlib
import traceback

from Registry import Registry
from impacket.examples.secretsdump import LocalOperations, SAMHashes, LSASecrets
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_DONT_EXPIRE_PASSWD

from regalyzer.utils import print_error, filetime_to_datetime, parse_v_string, format_report_dt, get_value

def run(console, image_root: str):
    """
    Executes the full SAM hive analysis if the required hives are found.
    """
    config_path = os.path.join(image_root, 'Windows', 'System32', 'config')
    sam_path = os.path.join(config_path, 'SAM')
    system_path = os.path.join(config_path, 'SYSTEM')
    security_path = os.path.join(config_path, 'SECURITY')

    if not os.path.exists(sam_path) or not os.path.exists(system_path):
        return False

    console.print(f"\n[bold green]===[/bold green] SAM User Accounts Analysis [bold green]===[/bold green]")
    console.print(f"Source SAM Hive: {sam_path}")

    try:
        # --- PART 1: Capture and Parse Hashes (Unchanged) ---
        local_ops = LocalOperations(system_path)
        boot_key = local_ops.getBootKey()
        sam_hashes = SAMHashes(sam_path, boot_key, isRemote=False)
        captured_output_buffer = io.StringIO()
        with contextlib.redirect_stdout(captured_output_buffer):
            sam_hashes.dump()
            sam_hashes.finish()
        captured_hashes_text = captured_output_buffer.getvalue()
        hash_lookup = {}
        for line in captured_hashes_text.splitlines():
            try:
                line = line.strip()
                if not line: continue
                parts = line.split(':')
                if len(parts) > 3:
                    rid = int(parts[1])
                    hash_lookup[rid] = {"ntlm": parts[3], "raw": line}
            except (ValueError, IndexError):
                continue

        # --- PART 2 & 3: Extract All Metadata and Combine ---
        reg = Registry.Registry(sam_path)
        users_key_path = "SAM\\Domains\\Account\\Users"
        users_key = reg.open(users_key_path)
        all_users = []

        for user_key in users_key.subkeys():
            if user_key.name() == "Names": continue

            rid = int(user_key.name(), 16)
            f_value_data = user_key.value("F").value()
            v_value_data = user_key.value("V").value()
            creation_time = user_key.timestamp()
            hash_data = hash_lookup.get(rid, {})

            # --- MODIFIED: Capture the source key for this specific user ---
            source_key_path = f"{users_key_path}\\{user_key.name()}"

            all_users.append({
                "RID": rid, "UserName": parse_v_string(v_value_data, 12, 16),
                "FullName": parse_v_string(v_value_data, 24, 28), "UserComment": parse_v_string(v_value_data, 36, 40),
                "CreationTime": creation_time, "LastLogon": filetime_to_datetime(struct.unpack_from("<Q", f_value_data, 8)[0]),
                "PwdLastSet": filetime_to_datetime(struct.unpack_from("<Q", f_value_data, 24)[0]),
                "AccountExpires": filetime_to_datetime(struct.unpack_from("<Q", f_value_data, 32)[0]),
                "LastIncorrectPassword": filetime_to_datetime(struct.unpack_from("<Q", f_value_data, 40)[0]),
                "LoginCount": struct.unpack_from("<H", f_value_data, 66)[0],
                "BadPasswordCount": struct.unpack_from("<H", f_value_data, 64)[0],
                "UserAccountControl": struct.unpack_from("<I", f_value_data, 48)[0],
                "NTLMHash": hash_data.get("ntlm", "Not Found"), "RawHashLine": hash_data.get("raw", "Not Found"),
                "SourceKey": source_key_path # --- ADDED: Store the source key path ---
            })

        # --- PART 4: Generate Report ---
        if not all_users:
            console.print("[yellow]No user entries were found in the SAM hive.[/yellow]")
            return True

        for user in sorted(all_users, key=lambda u: u['RID']):
            console.print("\n" + "="*80)
            console.print(f"[+] [bold magenta]User: {user.get('UserName', 'N/A')}[/bold magenta] (RID: {user.get('RID', 0)})")
            console.print("="*80)
            uac_flags = user.get('UserAccountControl', 0)

            # --- MODIFIED: Add "Source Key" to the report dictionary ---
            report = {
                "Full Name": user.get('FullName', 'N/A') or "N/A", "Username": user.get('UserName', 'N/A') or "N/A",
                "Comment": user.get('UserComment', 'N/A') or "N/A", "Account Created": format_report_dt(user.get('CreationTime')),
                "---": "---", "Last Login": format_report_dt(user.get('LastLogon')),
                "Password Last Set": format_report_dt(user.get('PwdLastSet')), "Last Incorrect Pwd": format_report_dt(user.get('LastIncorrectPassword')),
                "Account Expires": format_report_dt(user.get('AccountExpires')), "--- ": "---",
                "Login Count": user.get('LoginCount', 0), "Bad Password Count": user.get('BadPasswordCount', 0),
                "---  ": "---", "Account Disabled": "Yes" if uac_flags & UF_ACCOUNTDISABLE else "No",
                "Password Never Expires": "Yes" if uac_flags & UF_DONT_EXPIRE_PASSWD else "No",
                "---   ": "---",
                "Source Key": user.get("SourceKey", "Not Found"),
                "NTLM Hash": user.get("NTLMHash"),
                "Raw Hash Line": user.get("RawHashLine")
            }
            for key, value in report.items():
                console.print(f"  [cyan]{key:<25}:[/cyan] {value}")

        console.print("\n[bold]Cached Domain Logon Information (DCC2 / MSCache):[/bold]")
        try:
            lsa = LSASecrets(security_path, boot_key, isRemote=False)
            cached_hashes = lsa.dumpCachedHashes()

            if cached_hashes:
                cached_table = Table(title="Cached Credentials", show_lines=True)
                cached_table.add_column("Username", style="bold cyan", justify="left")
                cached_table.add_column("DCC2 Hash", style="white", justify="left")
                cached_table.add_column("Last Login (UTC)", style="green", justify="left")

                for user, hash_val, last_login in sorted(cached_hashes, key=lambda c: c[0]):
                    cached_table.add_row(user, hash_val, format_report_dt(last_login))
                console.print(cached_table)
            else:
                console.print("[dim]  No cached domain credentials found.[/dim]")

            console.print(f"\n[dim]-- Source Hives -> SECURITY, SYSTEM[/dim]")

        except Exception as e:
            print_error(f"Could not dump cached domain credentials: {e}", console)

    except Exception as e:
        print_error(f"An unexpected error occurred in the SAM parser: {e}")
        traceback.print_exc()
        return False
