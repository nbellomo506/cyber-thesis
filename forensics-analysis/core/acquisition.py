# file: core/acquisition.py
import os
import shutil
import ctypes
import subprocess

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def fetch_history_auto(dest_path="temp_history.txt"):
    user_profile = os.environ.get('USERPROFILE')
    history_path = os.path.join(user_profile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine', 'ConsoleHost_history.txt')
    if not os.path.exists(history_path):
        raise FileNotFoundError("File cronologia non trovato.")
    shutil.copy2(history_path, dest_path)
    return dest_path

def fetch_registry_standard(dest_path="temp_NTUSER.DAT"):
    user_profile = os.environ.get('USERPROFILE')
    ntuser_path = os.path.join(user_profile, 'NTUSER.DAT')
    if not os.path.exists(ntuser_path):
        raise FileNotFoundError("NTUSER.DAT non trovato.")
    shutil.copy2(ntuser_path, dest_path)
    return dest_path

def extract_via_vss(dest_path="temp_NTUSER.DAT"):
    if not is_admin():
        raise PermissionError("Privilegi Admin necessari per VSS.")
    user_profile = os.environ.get('USERPROFILE')
    drive_letter = os.path.splitdrive(user_profile)[0]
    user_dir = os.path.basename(user_profile)
    
    ps_script = f"""
    $drive = '{drive_letter}\\'
    $s1 = (Get-WmiObject -List Win32_ShadowCopy).Create($drive, "ClientAccessible")
    $s2 = Get-WmiObject Win32_ShadowCopy | Where-Object {{ $_.ID -eq $s1.ShadowID }}
    $device = $s2.DeviceObject
    $link = "C:\\vss_link"
    if (Test-Path $link) {{ cmd.exe /c rmdir $link }}
    cmd.exe /c mklink /d $link "$device\\"
    $src = "$link\\Users\\{user_dir}\\NTUSER.DAT"
    Copy-Item -Path "$src" -Destination "{dest_path}" -Force
    cmd.exe /c rmdir $link
    $s2.Delete()
    """
    subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    return dest_path

def export_powershell_evtx(dest_path="temp_PS_Operational.evtx"):
    """Esporta i log EVTX usando l'utility nativa wevtutil."""
    if not is_admin():
        raise PermissionError("Privilegi Admin necessari per esportare EVTX.")
    if os.path.exists(dest_path):
        os.remove(dest_path)
    log_name = "Microsoft-Windows-PowerShell/Operational"
    cmd = f'wevtutil epl "{log_name}" "{os.path.abspath(dest_path)}"'
    process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if process.returncode != 0:
        raise RuntimeError(f"Errore wevtutil: {process.stderr}")
    return dest_path