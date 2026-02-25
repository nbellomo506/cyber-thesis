import win32api
import win32con
import win32event
import threading
import time
from command_analyzer import MaliciousAnalyzer

analyzer = MaliciousAnalyzer()
REG_NOTIFY_CHANGE_LAST_SET = 0x00000004

WATCHLIST = [
    (win32con.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (win32con.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (win32con.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (win32con.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
]

registry_snapshots = {}

def get_key_snapshot(h_key):
    snapshot = {}
    try:
        count = win32api.RegQueryInfoKey(h_key)[1]
        for i in range(count):
            name, data, _ = win32api.RegEnumValue(h_key, i)
            snapshot[name] = data
    except Exception:
        pass
    return snapshot

def monitor_thread(root_key, path):
    root_name = "HKLM" if root_key == win32con.HKEY_LOCAL_MACHINE else "HKCU"
    full_path_display = f"{root_name}\\{path}"
    
    try:
        h_key = win32api.RegOpenKeyEx(root_key, path, 0, win32con.KEY_NOTIFY | win32con.KEY_READ)
        registry_snapshots[full_path_display] = get_key_snapshot(h_key)
        event = win32event.CreateEvent(None, 0, 0, None)
        print(f"[*] Monitoraggio avviato su: {full_path_display}")

        while True:
            win32api.RegNotifyChangeKeyValue(h_key, True, REG_NOTIFY_CHANGE_LAST_SET, event, True)
            win32event.WaitForSingleObject(event, win32event.INFINITE)
            
            new_snapshot = get_key_snapshot(h_key)
            old_snapshot = registry_snapshots.get(full_path_display, {})

            print(f"\n[!!!] ALERT EDR: Modifica rilevata in {full_path_display}")

            for name, data in new_snapshot.items():
                if name not in old_snapshot or old_snapshot[name] != data:
                    action = "MODIFICATO" if name in old_snapshot else "NUOVO"
                    print(f"    [+] Valore {action}: {name}")
                    report = analyzer.analyze_string(str(data))

                    if report["is_suspicious"]:
                        print(f"\n[!] ALERT: Trovata persistenza sospetta!")
                        print(f"    Motivi: {', '.join(report['reason'])}")
                        if report["decoded_content"]:
                            print(f"    DECODIFICATO: {report['decoded_content']}")

            registry_snapshots[full_path_display] = new_snapshot
            
    except Exception as e:
        print(f"[-] Errore su {path}: {e}")

def start_monitoring():
    """Funzione per far partire i thread"""
    for root, path in WATCHLIST:
        t = threading.Thread(target=monitor_thread, args=(root, path), daemon=True)
        t.start()