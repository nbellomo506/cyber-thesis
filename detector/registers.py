import winreg
import re

# Lista delle chiavi critiche dove spesso si nascondono i malware
TARGET_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"), # Controlla Shell e Userinit
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run")
]

# Pattern regex per identificare comportamenti potenzialmente malevoli nei comandi
PATTERN_SOSPETTI = [
    r"powershell",       # Spesso usato per scaricare payload
    r"-enc",             # Comandi codificati (spesso malevoli)
    r"-w hidden",        # Finestre nascoste
    r"\.vbs",            # Visual Basic Script
    r"\.js",             # JavaScript malevolo
    r"AppData\\Local\\Temp", # Esecuzione da cartelle temporanee
    r"cmd\.exe",         # Prompt dei comandi
    r"rundll32",         # Spesso usato per lanciare DLL malevole
]

def analizza_comando(comando):
    """
    Controlla se una stringa di comando contiene pattern sospetti.
    Restituisce una lista di motivi per cui è sospetto.
    """
    if not isinstance(comando, str):
        return []
    
    motivi = []
    for pattern in PATTERN_SOSPETTI:
        if re.search(pattern, comando, re.IGNORECASE):
            motivi.append(pattern)
    return motivi

def scan_registry_keys():
    
    print(f"{'='*60}")
    print(f"SCANSIONE REGISTRO PER SCRIPT DI PERSISTENZA")
    print(f"{'='*60}\n")

    for hive, subkey in TARGET_KEYS:
        hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
        full_path = f"{hive_name}\\{subkey}"
        
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                num_values = winreg.QueryInfoKey(key)[1]
                
                if num_values > 0:
                    print(f"[*] Scansione: {full_path}")
                    
                    for i in range(num_values):
                        try:
                            name, data, _ = winreg.EnumValue(key, i)
                            motivi_sospetti = analizza_comando(str(data))
                            
                            # Se troviamo pattern sospetti, usiamo un output evidenziato
                            if motivi_sospetti:
                                print(f"  [!] ALLERTA POTENZIALE: {name}")
                                print(f"      Comando: {data}")
                                print(f"      Motivo: Trovati pattern {motivi_sospetti}")
                                print("-" * 40)
                            else:
                                # Stampa informativa (puoi commentarla per vedere solo le allerte)
                                print(f"  [OK] {name}: {data[:60]}..." if len(str(data)) > 60 else f"  [OK] {name}: {data}")

                        except OSError:
                            continue
                    print("") # Spazio tra le chiavi
                
        except PermissionError:
            print(f"[X] Accesso Negato: {full_path} (Esegui come Amministratore per vedere questo)\n")
        except FileNotFoundError:
            # La chiave non esiste su questa macchina (normale per RunOnce)
            pass
    
    print("\nScansione terminata.")