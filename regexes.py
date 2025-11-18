suspicious_registry_regexes = [
    # Run / RunOnce / Policies / Wow6432Node
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce(\\.*)?$",
    r"^[^\\]+\\.DEFAULT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(\\.*)?$",
    r"^[^\\]+\\.DEFAULT\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run(\\.*)?$",
    r"^[^\\]+\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run(\\.*)?$",
    r"^[^\\]+\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce(\\.*)?$",
    r"^[^\\]+\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices(\\.*)?$",
    r"^[^\\]+\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx(\\.*)?$",
    r"^[^\\]+\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx(\\.*)?$",

    # Winlogon
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Taskman(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AppSetup(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GinaDLL(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon(\\.*)?$",

    # Shell / Explorer extensions
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Extensions\\Approved(\\.*)?$",

    # Context menu handlers
    r"^[^\\]+\\\*\\ShellEx\\ContextMenuHandlers(\\.*)?$",
    r"^[^\\]+\\Directory\\ShellEx\\ContextMenuHandlers(\\.*)?$",
    r"^[^\\]+\\AllFileSystemObjects\\ShellEx\\ContextMenuHandlers(\\.*)?$",

    # AppInit / Windows global injection
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs(\\.*)?$",
    r"^[^\\]+\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows(\\.*)?$",

    # Services / Session Manager
    r"^[^\\]+\\System\\CurrentControlSet\\Services(\\.*)?$",
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\Session Manager(\\.*)?$",
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\Session Manager\\BootExecute(\\.*)?$",
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs(\\.*)?$",
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls(\\.*)?$",

    # LSA packages
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\Lsa(\\.*)?$",
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\Lsa\\Authentication Packages(\\.*)?$",
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\Lsa\\Notification Packages(\\.*)?$",
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\Lsa\\Security Packages(\\.*)?$",

    # IFEO / SilentProcessExit
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options(\\.*)?$",
    r"^[^\\]+\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit(\\.*)?$",
    r"^[^\\]+\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit(\\.*)?$",

    # StartupApproved / Shell folders
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run32(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run32(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders(\\.*)?$",

    # Scheduled Tasks (TaskCache)
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks(\\.*)?$",

    # SafeBoot / NetworkProvider
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\SafeBoot(\\.*)?$",
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\SafeBoot\\Minimal(\\.*)?$",
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\SafeBoot\\Network(\\.*)?$",
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\NetworkProvider\\Order(\\.*)?$",
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\NetworkProvider\\ProviderOrder(\\.*)?$",

    # IE hooks / toolbars
    r"^[^\\]+\\Software\\Microsoft\\Internet Explorer\\URLSearchHooks(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Internet Explorer\\URLSearchHooks(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Internet Explorer\\Toolbar(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Internet Explorer\\Toolbar(\\.*)?$",

    # File type open command hijacking
    r"^[^\\]+\\exefile\\shell\\open\\command(\\.*)?$",
    r"^[^\\]+\\comfile\\shell\\open\\command(\\.*)?$",
    r"^[^\\]+\\batfile\\shell\\open\\command(\\.*)?$",
    r"^[^\\]+\\cmdfile\\shell\\open\\command(\\.*)?$",
    r"^[^\\]+\\piffile\\shell\\open\\command(\\.*)?$",
    r"^[^\\]+\\scrfile\\shell\\open\\command(\\.*)?$",

    # Active Setup
    r"^[^\\]+\\Software\\Microsoft\\Active Setup\\Installed Components(\\.*)?$",
    r"^[^\\]+\\Software\\Microsoft\\Active Setup\\Installed Components(\\.*)?$",

    # Print monitors / providers (DLL loading)
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\Print\\Monitors(\\.*)?$",
    r"^[^\\]+\\System\\CurrentControlSet\\Control\\Print\\Providers(\\.*)?$",
]


suspicious_file_path_regexes = [
    # Temp directories – executables / scripts
    r"^C:\\Windows\\Temp\\.+\.(exe|dll|sys|scr|com|bat|cmd|ps1|vbs|js)$",
    r"^C:\\Windows\\Temp\\[A-Za-z0-9]{5,}\.(tmp|dat|bin|log)$",
    r"^C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\.+\.(exe|dll|sys|scr|com|bat|cmd|ps1|vbs|js)$",
    r"^C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\[A-Za-z0-9]{6,}\.(tmp|dat|bin)$",
    r"^C:\\Users\\[^\\]+\\AppData\\LocalLow\\Temp\\.+\.(exe|dll|sys|scr|com|bat|cmd|ps1|vbs|js)$",

    # AppData\Roaming / Local – generic suspicious binaries
    r"^C:\\Users\\[^\\]+\\AppData\\(Local|Roaming)\\[A-Za-z0-9 _\-]{3,}\\.+\.(exe|dll|sys|scr|com|bat|cmd|ps1|vbs|js)$",
    r"^C:\\Users\\[^\\]+\\AppData\\(Local|Roaming)\\[A-Za-z0-9]{6,}\\[A-Za-z0-9]{6,}\.(exe|dll|dat|bin)$",
    r"^C:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Windows\\INetCache\\.+\.(exe|dll|scr|ps1|vbs|js)$",
    r"^C:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Windows\\INetCookies\\.+\.(exe|dll|scr|ps1|vbs|js)$",

    # Downloads / Desktop – risky script/exe types
    r"^C:\\Users\\[^\\]+\\Downloads\\.+\.(exe|scr|ps1|vbs|js|jse|wsf|bat|cmd)$",
    r"^C:\\Users\\[^\\]+\\Desktop\\.+\.(exe|scr|ps1|vbs|js|jse|wsf|bat|cmd)$",

    # Startup folders (user + common)
    r"^C:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\.+\.(lnk|exe|vbs|js|cmd|bat|ps1)$",
    r"^C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\.+\.(lnk|exe|vbs|js|cmd|bat|ps1)$",

    # ProgramData – random dirs with binaries
    r"^C:\\ProgramData\\[A-Za-z0-9 _\-]{3,}\\.+\.(exe|dll|sys|scr|com|bat|cmd|ps1|vbs|js)$",
    r"^C:\\ProgramData\\[A-Za-z0-9]{6,}\\[A-Za-z0-9]{6,}\.(tmp|dat|bin|exe|dll)$",

    # Public user – executables in shared folders
    r"^C:\\Users\\Public\\(Documents|Downloads|Music|Pictures|Videos)\\.+\.(exe|scr|ps1|vbs|js|bat|cmd)$",
    r"^C:\\Users\\Public\\[A-Za-z0-9 _\-]{3,}\\.+\.(exe|scr|ps1|vbs|js|bat|cmd)$",

    # Root of any drive – loose binaries
    r"^[A-Z]:\\[^\\]{3,}\.(exe|dll|sys|scr|com|bat|cmd|ps1|vbs|js)$",
    r"^[A-Z]:\\[A-Za-z0-9 _\-]{3,}\\[A-Za-z0-9 _\-]{3,}\.(exe|dll|sys|scr)$",

    # Recycle Bin – executables/scripts inside
    r"^[A-Z]:\\\$RECYCLE\.BIN\\.+\.(exe|dll|scr|bat|cmd|ps1|vbs|js)$",

    # Suspicious inside Windows directory (non-standard names)
    r"^C:\\Windows\\[A-Za-z0-9 _\-]{4,}\.(exe|dll|scr|com|bat|cmd|ps1|vbs|js)$",
    r"^C:\\Windows\\System32\\[A-Za-z0-9]{6,}\d{2}\.(exe|dll|sys)$",
    r"^C:\\Windows\\SysWOW64\\[A-Za-z0-9]{6,}\d{2}\.(exe|dll|sys)$",

    # Spool / Print – abused for DLL drop
    r"^C:\\Windows\\System32\\spool\\drivers\\color\\.+\.(exe|dll|scr)$",
    r"^C:\\Windows\\System32\\spool\\drivers\\x64\\.+\.(exe|dll|scr)$",

    # Hidden-ish random folders under user profile
    r"^C:\\Users\\[^\\]+\\[A-Za-z0-9]{5,}\\[A-Za-z0-9]{5,}\.(exe|dll|dat|bin)$",

    # AppData\Local\Microsoft\Windows\{random}\{random}.exe
    r"^C:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Windows\\[A-Za-z0-9]{6,}\\[A-Za-z0-9]{6,}\.(exe|dll|dat)$",

    # AppData\Roaming\{random vendor}\{random product}\.exe
    r"^C:\\Users\\[^\\]+\\AppData\\Roaming\\[A-Za-z0-9]{4,}\\[A-Za-z0-9]{4,}\.(exe|dll|dat)$",

    # Temp under ProgramData
    r"^C:\\ProgramData\\Temp\\.+\.(exe|dll|sys|scr|com|bat|cmd|ps1|vbs|js)$",

    # Suspicious scripts dropped under AppData\Local\Temp subdirs
    r"^C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\[A-Za-z0-9]{3,}\\.+\.(ps1|vbs|js|jse|wsf)$",

    # MSI / setup-like names in Temp / AppData
    r"^C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\(setup|install|update|patch)[A-Za-z0-9_\-]*\.(exe|msi|bat|cmd)$",
    r"^C:\\Users\\[^\\]+\\AppData\\Local\\(Temp|Temp\\[A-Za-z0-9]{3,})\\[A-Za-z0-9]{8,}\.(msi|cab|dat|bin)$",

    # Office / Office-related temp executables
    r"^C:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Office\\.+\.(exe|dll|scr|ps1|vbs)$",

    # OneDrive / Sync folders – executables
    r"^C:\\Users\\[^\\]+\\OneDrive\\.+\.(exe|dll|scr|ps1|vbs|js)$",
    r"^C:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\OneDrive\\.+\.(exe|dll|scr)$",

    # Edge / Chrome / browser data – dropped binaries
    r"^C:\\Users\\[^\\]+\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\.+\.(exe|dll|scr|ps1|vbs|js)$",
    r"^C:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\.+\.(exe|dll|scr|ps1|vbs|js)$",
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