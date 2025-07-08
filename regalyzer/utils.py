# regalyzer/utils.py

"""
Regalyzer Toolkit - Shared Utility Functions
"""
import struct
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
