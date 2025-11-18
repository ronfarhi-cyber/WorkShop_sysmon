import re
import functools
from typing import List
import tldextract
import requests


suspicious_registry_regexes = [
    # --- Autostart Run Keys ---
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce(\\.*)?$",
    r"^[^\\]+\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run(\\.*)?$",

    # --- Winlogon Persistence ---
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\(Shell|Userinit|GinaDLL|VmApplet)(\\.*)?$",

    # --- Global DLL Injection (AppInit_DLLs) ---
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs(\\.*)?$",
    r"^[^\\]+\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs(\\.*)?$",

    # --- Session Manager Hooks ---
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\Session Manager\\(AppCertDlls|BootExecute|KnownDLLs)(\\.*)?$",

    # --- LSA Authentication Packages ---
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\Lsa\\(Authentication Packages|Notification Packages|Security Packages)(\\.*)?$",

    # --- Image File Execution Options / SilentProcessExit ---
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\[^\\]+(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\[^\\]+(\\.*)?$",

    # --- Scheduled Tasks (TaskCache) ---
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\(Tree|Tasks)(\\.*)?$",

    # --- StartupApproved (hidden startup entries) ---
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\(Run|Run32|StartupFolder)(\\.*)?$",

    # --- Active Setup (Run-once user initialization) ---
    r"^[^\\]+\\Software\\Microsoft\\Active Setup\\Installed Components(\\.*)?$",

    # --- SafeBoot (persistence via Safe Mode) ---
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\SafeBoot\\(AlternateShell|Minimal|Network)(\\.*)?$",

    # --- Terminal Server startup programs ---
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\StartupPrograms(\\.*)?$",

    # --- Svchost service groups (malicious grouping) ---
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Svchost(\\.*)?$",

    # --- ScreenSaver persistence (SCRNSAVE.EXE abuse) ---
    r"^[^\\]+\\Control Panel\\Desktop(\\.*)?$",

    # --- Netsh helper DLL injection ---
    r"^[^\\]+\\Software\\Microsoft\\Netsh(\\.*)?$",
]

suspicious_file_path_regexes = [
    # --- Temp Executables / Scripts ---
    r"^C:\\(Windows|Users\\[^\\]+\\AppData\\(Local|LocalLow))\\Temp\\.+\.(exe|dll|sys|scr|bat|cmd|ps1|vbs|js)$",

    # --- AppData Local/Roaming Suspicious Binaries ---
    r"^C:\\Users\\[^\\]+\\AppData\\(Local|Roaming)\\[A-Za-z0-9 _\-]{3,}\\[^\\]+\\.+\.(exe|dll|dat|bin|scr|ps1|vbs|js)$",

    # --- Startup Folders (User + All Users) ---
    r"^C:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\.+\.(lnk|exe|vbs|js|cmd|bat|ps1)$",
    r"^C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\.+\.(lnk|exe|vbs|js|cmd|bat|ps1)$",

    # --- ProgramData hidden binaries ---
    r"^C:\\ProgramData\\[A-Za-z0-9 _\-]{4,}\\.+\.(exe|dll|dat|bin)$",
    r"^C:\\ProgramData\\Temp\\.+\.(exe|dll|sys|scr)$",

    # --- Public / Shared Executables ---
    r"^C:\\Users\\Public\\.+\.(exe|dll|scr|bat|cmd|ps1|vbs|js)$",

    # --- Random executables directly under drive root ---
    r"^[A-Z]:\\[^\\]{3,}\.(exe|dll|sys|scr|ps1|bat|cmd|vbs|js)$",

    # --- Suspicious executables in Windows directories ---
    r"^C:\\Windows\\(System32|SysWOW64)\\[A-Za-z0-9]{5,}\d{2}\.(exe|dll|sys)$",
    r"^C:\\Windows\\Temp\\.+\.(exe|dll|sys|bat|cmd|ps1)$",

    # --- Tasks & Jobs ---
    r"^C:\\Windows\\(System32\\)?Tasks\\.+$",

    # --- Prefetch / Fonts / Security folders abuse ---
    r"^C:\\Windows\\(Prefetch|Fonts|security|assembly|debug)\\.+\.(exe|dll|scr)$",

    # --- Fake system processes in wrong locations ---
    r"^C:\\ProgramData\\[^\\]+\\(svchost|lsass|explorer|csrss|winlogon|smss)\.exe$",

    # --- AppData\Roaming\Microsoft\Network RAT persistence ---
    r"^C:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Network\\.+\.(exe|dll|scr|ps1|vbs|js)$",

    # --- Random EXE/DLL in user root ---
    r"^C:\\Users\\[^\\]+\\[A-Za-z0-9 _\-]{3,}\.(exe|dll|scr|ps1|vbs|js)$",
]



known_driver_name_regexes = [
    # Core Windows storage / filesystem
    r"^disk\.sys$",
    r"^partmgr\.sys$",
    r"^volmgr\.sys$",
    r"^volmgrx\.sys$",
    r"^volsnap\.sys$",
    r"^mountmgr\.sys$",
    r"^ntfs\.sys$",
    r"^fastfat\.sys$",
    r"^fltmgr\.sys$",
    r"^fileinfo\.sys$",
    r"^fs_rec\.sys$",
    r"^dmio\.sys$",
    r"^dmload\.sys$",
    r"^cdrom\.sys$",
    r"^storport\.sys$",
    r"^storahci\.sys$",
    r"^atapi\.sys$",
    r"^pciide\.sys$",

    # Kernel / HAL / memory
    r"^hal\.dll$",
    r"^halacpi\.dll$",
    r"^pci\.sys$",
    r"^acpi\.sys$",
    r"^ndis\.sys$",
    r"^win32k\.sys$",
    r"^win32kbase\.sys$",
    r"^win32kfull\.sys$",
    r"^win32kgraph\.sys$",

    # Networking stack
    r"^tcpip\.sys$",
    r"^netbt\.sys$",
    r"^afd\.sys$",
    r"^tdx\.sys$",
    r"^fwpkclnt\.sys$",
    r"^dnsrslvr\.dll$",
    r"^netio\.sys$",
    r"^nsi\.dll$",
    r"^http\.sys$",

    # USB / HID / input
    r"^usbport\.sys$",
    r"^usbehci\.sys$",
    r"^usbohci\.sys$",
    r"^usbuhci\.sys$",
    r"^usbxhci\.sys$",
    r"^usbccgp\.sys$",
    r"^usbstor\.sys$",
    r"^hidclass\.sys$",
    r"^hidparse\.sys$",
    r"^mouclass\.sys$",
    r"^kbdclass\.sys$",
    r"^mouhid\.sys$",
    r"^kbdhid\.sys$",

    # Graphics / display
    r"^dxgkrnl\.sys$",
    r"^dxgmms1\.sys$",
    r"^dxgmms2\.sys$",
    r"^BasicDisplay\.sys$",
    r"^BasicRender\.sys$",
    r"^igdkmd64\.sys$", # Intel
    r"^nvlddmkm\.sys$", # NVIDIA
    r"^atikmdag\.sys$", # AMD (ישן)
    r"^amdkmdag\.sys$", # AMD (חדש יותר)

    # Audio
    r"^portcls\.sys$",
    r"^drmk\.sys$",
    r"^hdaudbus\.sys$",
    r"^ks\.sys$",

    # PnP / BIOS / system
    r"^msisadrv\.sys$",
    r"^pciidex\.sys$",
    r"^intelppm\.sys$",
    r"^amdk8\.sys$",
    r"^amdppm\.sys$",
    r"^vdrvroot\.sys$",
    r"^hwpolicy\.sys$",
    r"^hwdrv\.sys$",

    # File system filter drivers נפוצים (לגיטימיים)
    r"^Wof\.sys$",
    r"^rdyboost\.sys$",
    r"^WdFilter\.sys$", # Windows Defender filesystem filter
    r"^luafv\.sys$",
    r"^storflt\.sys$",
    r"^wcifs\.sys$",
    r"^cldflt\.sys$",

    # Virtualization (לגיטימי)
    r"^vmswitch\.sys$",
    r"^vmstorfl\.sys$",
    r"^vmbus\.sys$",
    r"^intelide\.sys$",
    r"^VBoxGuest\.sys$",
    r"^VBoxSF\.sys$",
    r"^VBoxVideo\.sys$",
    r"^VBoxMouse\.sys$",
    r"^vmxnet3\.sys$",
    r"^vmhgfs\.sys$",
    r"^vm3dmp\.sys$",
    r"^vmmouse\.sys$",

    # Bluetooth / wireless – שמות נפוצים (כלליים)
    r"^btfilter\.sys$",
    r"^bthport\.sys$",
    r"^bthusb\.sys$",
    r"^netr28x\.sys$",
    r"^netwsw.*\.sys$",
    r"^rtwlane\.sys$",
    r"^rtwlanu\.sys$",

    # Storage vendor (דוגמאות כלליות, לא ספציפי למוצר)
    r"^iaStor[A-Za-z0-9]*\.sys$",
    r"^lsi_sas\.sys$",
    r"^megasas\.sys$",
    r"^nvstor\.sys$",
    r"^amdsata\.sys$",
    r"^amd_sata\.sys$",

    # Touchpad / input vendors
    r"^SynTP\.sys$",
    r"^ETD\.sys$",
    r"^Apfiltr\.sys$",
    r"^Elantech\.sys$",
    r"^i8042prt\.sys$",

    # VPN / tunneling drivers (שמות כלליים, חוקיים)
    r"^tap0901\.sys$",
    r"^tap-windows6?\.sys$",
    r"^nettap\.sys$",
    r"^e2evpn\.sys$",
]

def matches_any_pattern(patterns: List[str], text: str) -> bool:
    for pat in patterns:
        if re.search(pat, text):
            return True
    return False

@functools.cache
def check_registry_path(path: str) -> bool:
    """
    The fucntion expact r"" string type
    """
    return matches_any_pattern(suspicious_registry_regexes, path)

@functools.cache
def check_file_path(path: str) -> bool:
    """
    The fucntion expact r"" string type
    """
    return matches_any_pattern(suspicious_file_path_regexes, path)

@functools.cache
def check_driver_name(name: str) -> bool:
    """
    The fucntion expact r"" string type
    """
    return matches_any_pattern(known_driver_name_regexes, name)


@functools.cache
def check_ip_or_domain(target: str):
    """
    Checks if a domain or IP is suspicious.

    Returns:
    - Reason/comments from AbuseIPDB if flagged
    - 'suspicious tld' if domain has high-risk TLD
    - None if not suspicious
    """


    ABUSEIPDB_API_KEY = "3ca59885ae1cb6b0e02b24582aa784d81e61dac37deb0a832b188c45db701a16f326caddbaf83ea1"
    HIGH_RISK_TLDS = ['ir', 'kp', 'ru', 'sy', 'af', 'pk', 'iq']


    # Step 1: Try AbuseIPDB first
    abuseip_result = None
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress": target,
                "maxAgeInDays": 90
            },
            timeout=30  # avoid hanging
        )
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and data['data']['abuseConfidenceScore'] > 0:
                reports = data['data'].get('reports', [])
                if reports:
                    abuseip_result = reports[0].get('comment', 'abuseip report found, reason unknown')
                else:
                    abuseip_result = "abuseip report found, reason unknown"
        else:
            print(f"AbuseIPDB API returned status code {response.status_code}, skipping AbuseIPDB check.")
    except Exception as e:
        print(f"AbuseIPDB check failed ({e}), skipping to TLD check.")

    if abuseip_result:
        return abuseip_result

    # Step 2: Check TLD
    extracted = tldextract.extract(target)
    tld = extracted.suffix.lower()
    if tld in HIGH_RISK_TLDS:
        return "suspicious tld"

    # Step 3: Nothing suspicious found
    return None






# exapmle:
# print(check_driver_name(r"http.sys"))