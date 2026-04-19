# file: core/acquisition.py
import os
import shutil
import ctypes
import subprocess

def is_admin():
    """Verifica se il processo ha privilegi di amministratore."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def fetch_history_auto(dest_path="temp_history.txt"):
    """Copia la cronologia di PS nella cartella di lavoro."""
    user_profile = os.environ.get('USERPROFILE')
    history_path = os.path.join(user_profile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine', 'ConsoleHost_history.txt')
    
    if not os.path.exists(history_path):
        raise FileNotFoundError("Il file di cronologia PowerShell non è presente su questo sistema.")
        
    shutil.copy2(history_path, dest_path)
    return dest_path

def fetch_registry_standard(dest_path="temp_NTUSER.DAT"):
    """Tenta l'acquisizione standard di NTUSER.DAT."""
    user_profile = os.environ.get('USERPROFILE')
    ntuser_path = os.path.join(user_profile, 'NTUSER.DAT')
    
    if not os.path.exists(ntuser_path):
        raise FileNotFoundError("NTUSER.DAT non trovato sul sistema.")
        
    shutil.copy2(ntuser_path, dest_path) # Questo solleverà PermissionError se bloccato
    return dest_path

def extract_via_vss(dest_path="temp_NTUSER.DAT"):
    """Forza l'estrazione di NTUSER.DAT usando Volume Shadow Copy."""
    if not is_admin():
        raise PermissionError("Privilegi Insufficienti per VSS. Avvia come Amministratore.")

    user_profile = os.environ.get('USERPROFILE')
    drive_letter = os.path.splitdrive(user_profile)[0]
    user_dir = os.path.basename(user_profile)
    
    ps_script = f"""
    $drive = '{drive_letter}\\'
    $s1 = (Get-WmiObject -List Win32_ShadowCopy).Create($drive, "ClientAccessible")
    if ($s1.ReturnValue -ne 0) {{ throw "Errore VSS: $($s1.ReturnValue)" }}
    
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
    
    process = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
        capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
    )
    
    if os.path.exists(dest_path) and os.path.getsize(dest_path) > 0:
        return dest_path
    else:
        raise RuntimeError(f"Errore VSS PS: {process.stderr}")