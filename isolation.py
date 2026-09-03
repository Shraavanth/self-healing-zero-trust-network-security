from datetime import datetime

from logger import log_event


isolated_devices = {}


def isolate_device(ip_address, mac_address=None, reason=None):
    """Mark a device as isolated."""

    isolated_devices[ip_address] = {
        "mac_address": mac_address,
        "reason": reason,
        "isolated_at": datetime.now().isoformat()
    }

    log_event(
        "DEVICE_ISOLATED",
        {
            "ip": ip_address,
            "mac": mac_address,
            "reason": reason
        }
    )

    print("\n[DEVICE ISOLATED]")
    print(f"IP: {ip_address}")
    print(f"MAC: {mac_address}")
    print(f"Reason: {reason}")

    return True


def restore_device(ip_address):
    """Restore a previously isolated device."""

    if ip_address not in isolated_devices:
        print(f"\n[RESTORE] Device {ip_address} is not currently isolated.")
        return False

    device = isolated_devices.pop(ip_address)

    log_event(
        "DEVICE_RESTORED",
        {
            "ip": ip_address,
            "mac": device.get("mac_address"),
            "reason": "Trust score recovered"
        }
    )

    print("\n[DEVICE RESTORED]")
    print(f"IP: {ip_address}")

    return True


def is_device_isolated(ip_address):
    """Check whether a device is currently isolated."""

    return ip_address in isolated_devices


def get_isolated_devices():
    """Return all currently isolated devices."""

    return isolated_devices