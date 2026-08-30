# Packet Capture - Npcap Installation Guide

## Problem
The packet capture script fails with error:
```
RuntimeError: Sniffing and sending packets is not available at layer 2: 
winpcap is not installed.
```

This error appears because **Npcap** (the Windows packet capture driver) is not installed on your system.

## Solution

### Option 1: Install Npcap (Recommended) ✅

Npcap is a Windows library that allows raw packet access. It's required for any packet sniffing on Windows.

#### Steps:
1. **Download Npcap**
   - Visit: https://nmap.org/npcap/
   - Download the latest installer (usually `npcap-installer.exe`)

2. **Install Npcap**
   - Run the installer with Administrator privileges
   - Follow the installation wizard
   - When asked about "WinPcap API-compatible mode", select "Install" (this ensures compatibility)
   - Complete the installation

3. **Restart your computer**
   - Npcap requires a system restart to load the driver

4. **Run the script**
   ```powershell
   python packet_capture.py
   ```

### Option 2: Check System Requirements

After Npcap installation, ensure:
- ✓ Your system is Windows 7 or later
- ✓ You have administrator privileges
- ✓ Network adapter is properly recognized by Windows
- ✓ Npcap service is running

To verify Npcap is working:
```powershell
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

This should NOT show: `WARNING: No libpcap provider available`

### Option 3: Run with Administrator Privileges

Even with Npcap installed, you may need to run the script with admin privileges:
```powershell
# In PowerShell (as Administrator)
python packet_capture.py
```

## File Updates

- **config.py**: Updated with the correct active network interface GUID
- **packet_capture.py**: Enhanced with better error messages and guidance
- **packet_capture_l3.py**: Alternative Layer 3 capture (still requires Npcap on Windows)

## Important Notes

- Layer 3 sniffing (`packet_capture_l3.py`) also requires Npcap on Windows
- macOS users use `pcap` (built-in)
- Linux users use `libpcap` (usually pre-installed)
- Windows exclusively requires Npcap for packet sniffing with Scapy

## Troubleshooting

If you still get errors after Npcap installation:

1. **Check if Npcap driver loaded**
   ```powershell
   Get-Service | grep -i npcap
   ```

2. **Reinstall Npcap**
   - Uninstall completely via Control Panel
   - Restart
   - Download and reinstall fresh from https://nmap.org/npcap/

3. **Check network adapter**
   - Ensure your network adapter is not disabled
   - Try a different network interface if available

4. **Update drivers**
   - Update your network adapter drivers from manufacturer's website

## References

- Npcap: https://nmap.org/npcap/
- Scapy Documentation: https://scapy.readthedocs.io/
- Scapy Windows Issues: https://scapy.readthedocs.io/en/latest/troubleshooting.html
