# file: core/parsers.py
import codecs
from Registry import Registry

def parse_powershell_log(file_path):
    """Legge un file di log testuale e restituisce i comandi."""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        commands = f.readlines()
    return [cmd.strip() for cmd in commands if cmd.strip()]

def parse_ntuser_dat(file_path):
    """Estrae i comandi sospetti dai domini forensi del registro."""
    entries_found = []
    reg = Registry.Registry(file_path)

    # Dominio A: Persistenza Classica
    for path in [r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"]:
        try:
            for value in reg.open(path).values():
                entries_found.append({"source": f"Registry Run ({value.name()})", "command": str(value.value())})
        except Registry.RegistryKeyNotFoundException: pass

    # Dominio B: UserAssist (ROT13 Decoded)
    try:
        userassist_key = reg.open(r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
        for subkey in userassist_key.subkeys():
            if subkey.subkeys():
                for value in subkey.subkey("Count").values():
                    clear_name = codecs.decode(value.name(), 'rot_13')
                    if any(ext in clear_name.lower() for ext in ['.exe', 'powershell', 'cmd', '.bat', '.ps1', '.vbs']):
                        entries_found.append({"source": "UserAssist (Decoded)", "command": clear_name})
    except Registry.RegistryKeyNotFoundException: pass

    # Dominio C: RunMRU
    try:
        runmru_key = reg.open(r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")
        for value in runmru_key.values():
            if value.name() != "MRUList":
                entries_found.append({"source": "RunMRU History", "command": str(value.value())})
    except Registry.RegistryKeyNotFoundException: pass

    # Dominio D: Environment Variables
    try:
        for value in reg.open(r"Environment").values():
            val_data = str(value.value())
            if len(val_data) > 80 or any(kw in val_data.lower() for kw in ['iex', 'bypass', '-enc', 'powershell']):
                entries_found.append({"source": f"Environment Var ({value.name()})", "command": val_data})
    except Registry.RegistryKeyNotFoundException: pass

    return entries_found