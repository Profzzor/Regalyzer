# regalyzer/utils.py

"""
Regalyzer Toolkit - Shared Utility Functions
"""
import struct
import os
import re
from datetime import datetime, timezone, timedelta
from rich.console import Console
from rich.panel import Panel
from Registry import Registry

def print_error(message: str):
    """Prints a formatted error message."""
    console = Console()
    console.print(Panel(f"[bold red]ERROR:[/bold red] {message}", title="Error", border_style="red"))

def filetime_to_datetime(filetime: int):
    """Converts a Windows FILETIME, handling special 'never' values."""
    if filetime == 0 or filetime == 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=filetime // 10)
    except OverflowError:
        return None

def parse_v_string(v_data, offset_loc, len_loc):
    """Helper to parse a string from the V data blob."""
    try:
        offset = struct.unpack_from("<I", v_data, offset_loc)[0] + 0xCC
        length = struct.unpack_from("<I", v_data, len_loc)[0]
        if length > 0:
            return v_data[offset : offset + length].decode('utf-16-le', errors='replace')
    except (struct.error, IndexError):
        return None
    return None

def format_report_dt(dt):
    """Formats a datetime object for the final report."""
    return dt.strftime('%Y-%m-%d %H:%M:%S') if dt else "N/A"

def get_value(key, value_name, default="Not Found"):
    """Safely get a value from a registry key."""
    try:
        return key.value(value_name).value()
    except Registry.RegistryValueNotFoundException:
        return default

def format_timestamp(ts, default="N/A"):
    """Safely format a Unix timestamp."""
    if not isinstance(ts, int) or ts == 0:
        return default
    try:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
    except (ValueError, OSError):
        return "Invalid Timestamp"

def clean_multi_sz(value):
    """Cleans a REG_MULTI_SZ list by removing empty strings and returns a list."""
    if not isinstance(value, list):
        return [value] if value and value != "N/A" else []
    return [item for item in value if item]

def format_datetime_obj(dt_obj):
    """
    Safely formats a datetime object into a string.
    Works for both key timestamps and FILETIME values read by the library.
    """
    from datetime import datetime # Import here to avoid circular dependencies
    if isinstance(dt_obj, datetime):
        return dt_obj.strftime('%Y-%m-%d %H:%M:%S')
    return "N/A"

def find_timestamp_value(start_key, key_name_suffix_to_find):
    """
    This proven recursive function finds a key ending in a specific suffix
    and returns its default value. Handles corrupted keys.
    """
    from Registry import RegistryParse # Import here
    try:
        if start_key.name().endswith(key_name_suffix_to_find):
            return get_value(start_key, "(default)")
        for subkey in start_key.subkeys():
            found = find_timestamp_value(subkey, key_name_suffix_to_find)
            if found != "N/A":
                return found
    except (RegistryParse.UnknownTypeException, AttributeError):
        pass
    return "N/A"
    
def format_filetime(filetime: int):
    """Correctly parses a 64-bit Windows FILETIME value."""
    from datetime import datetime, timezone, timedelta # Local import
    if not isinstance(filetime, int) or filetime == 0:
        return "N/A"
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=filetime // 10)).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, OSError):
        return "Invalid Timestamp"

def parse_shell_item_path(data):
    """A simplified parser for shell items to extract the path string."""
    import struct # Local import
    try:
        if not isinstance(data, bytes) or len(data) < 4: return "[Invalid Data]"
        path_parts = []
        offset = 0
        while offset < len(data):
            item_size = struct.unpack_from('<H', data, offset)[0]
            if item_size == 0: break
            item_data = data[offset : offset + item_size]
            item_type = item_data[2]
            path_segment = None
            if item_type in [0x31, 0x32, 0xb1]:
                path_segment = item_data.split(b'\x00\x00')[0].decode('utf-16-le', 'ignore').split('\x00')[0]
            elif item_type == 0x2f:
                path_segment = item_data[3:].split(b'\x00')[0].decode('ascii', 'ignore')
            if path_segment: path_parts.append(path_segment)
            offset += item_size
        return '\\'.join(path_parts)
    except Exception: return "[Parsing Error]"

def get_user_profiles(image_root, console):
    """
    Finds all user profiles by parsing the SOFTWARE hive.
    This function is platform-independent and correctly handles and normalizes
    Windows paths regardless of the host OS.
    """

    software_path = os.path.join(image_root, 'Windows', 'System32', 'config', 'SOFTWARE')
    if not os.path.exists(software_path):
        print_error("Required SOFTWARE hive not found for user analysis.", console)
        return []

    user_profiles = []
    try:
        reg_software = Registry.Registry(software_path)
        profile_list_key = reg_software.open("Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
        
        for sid_key in profile_list_key.subkeys():
            profile_path_raw = get_value(sid_key, "ProfileImagePath", "")
            if not profile_path_raw: continue

            # --- THE DEFINITIVE PLATFORM-INDEPENDENT FIX ---
            # 1. Manually expand common environment variables.
            # Replace backslashes with forward slashes for consistency before processing.
            clean_path = profile_path_raw.replace('\\', '/')
            clean_path = clean_path.replace('%SystemRoot%', 'Windows')
            clean_path = clean_path.replace('%systemroot%', 'Windows')
            
            # 2. Use a regular expression to reliably remove drive letters (e.g., "C:")
            path_no_drive = re.sub(r'^[a-zA-Z]:/', '', clean_path)
            
            # 3. Create the full path relative to our image root
            # and normalize it for the current operating system.
            relative_path = path_no_drive.strip('/')
            final_profile_path = os.path.normpath(os.path.join(image_root, relative_path))
            
            username = os.path.basename(final_profile_path)
            
            # 4. Add the user profile with now-correct paths.
            user_profiles.append({
                "username": username,
                "sid": sid_key.name(),
                "profile_path": final_profile_path,
                "ntuser_path": os.path.join(final_profile_path, "NTUSER.DAT"),
                "usrclass_path": os.path.join(final_profile_path, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat")
            })

    except Exception as e:
        print_error(f"Could not parse user profiles from SOFTWARE hive: {e}", console)
    
    return user_profiles

def parse_systemtime_from_binary(data):
    """
    Correctly parses a 16-byte SYSTEMTIME structure from a REG_BINARY value.
    """
    try:
        if not isinstance(data, bytes) or len(data) < 16:
            return "N/A"
        
        # Unpack the 8 WORDs (2-byte unsigned integers) of a SYSTEMTIME struct
        year, month, day_of_week, day, hour, minute, second, milliseconds = struct.unpack('<HHHHHHHH', data)
        
        # A year of 0 indicates an empty/null timestamp
        if year == 0:
            return "N/A"
            
        return datetime(year, month, day, hour, minute, second).strftime('%Y-%m-%d %H:%M:%S')
    except (struct.error, ValueError):
        return "[Parsing Error]"

def format_mac_address(mac_bytes):
    """Formats a binary MAC address into a human-readable string."""
    if not isinstance(mac_bytes, bytes) or len(mac_bytes) < 6:
        return "N/A"
    return ':'.join(f'{b:02X}' for b in mac_bytes)
