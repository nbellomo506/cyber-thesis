# file: core/parsers.py
import codecs
import os
from Registry import Registry
from datetime import datetime

try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    import xml.etree.ElementTree as ET
except ImportError:
    print("[!] Libreria python-evtx non trovata. L'analisi EVTX non funzionerà.")

def format_timestamp(timestamp):
    if timestamp:
        try: return timestamp.strftime("%d-%m-%Y %H:%M:%S")
        except: return "Timestamp Errato"
    return "N/D"

def parse_powershell_log(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        commands = f.readlines()
    try:
        mtime = os.path.getmtime(file_path)
        ts = f"{datetime.fromtimestamp(mtime).strftime('%d-%m-%Y %H:%M:%S')} (File)" 
    except: 
        ts = "N/D"
    return [{"source": "Console_History", "command": c.strip(), "timestamp": ts} for c in commands if c.strip()]

def parse_evtx_logs(file_path):
    """Versione robusta e sicura per l'estrazione dai log operativi EVTX con data EU."""
    entries = []
    ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
    
    try:
        with Evtx(file_path) as evtx_log:
            for xml, record in evtx_file_xml_view(evtx_log.get_file_header()):
                try:
                    root = ET.fromstring(xml)
                    system = root.find(f'{ns}System')
                    event_id = system.find(f'{ns}EventID').text
                    
                    # Cerchiamo lo Script Block Logging (EID 4104)
                    if event_id == '4104':
                        time_created = system.find(f'{ns}TimeCreated').attrib.get('SystemTime')
                        
                        # --- FIX FORMATO DATA SUPER ROBUSTO ---
                        if time_created:
                            try:
                                # 1. Rimuove Z e i millisecondi (es. .123456)
                                clean_time = time_created.split('.')[0].replace('Z', '')
                                # 2. Normalizza: se c'è una 'T', la trasforma in spazio
                                clean_time = clean_time.replace('T', ' ')
                                # 3. Ora il formato è garantito essere Anno-Mese-Giorno Ora:Minuti:Secondi
                                dt = datetime.strptime(clean_time, "%Y-%m-%d %H:%M:%S")
                                # 4. Converte in formato italiano
                                ts_str = dt.strftime("%d-%m-%Y %H:%M:%S")
                            except Exception as e:
                                # Fallback: se fallisce, stampa il dato grezzo senza microsecondi
                                ts_str = time_created.split('.')[0].replace('T', ' ')
                                print(f"[?] Formato data atipico EVTX bypassato: {time_created}")
                        else:
                            ts_str = "N/D"
                        # --------------------------------------
                        
                        event_data = root.find(f'{ns}EventData')
                        if event_data is not None:
                            for data in event_data.findall(f'{ns}Data'):
                                if data.attrib.get('Name') == 'ScriptBlockText' and data.text:
                                    # Rimuoviamo gli a capo per non spaccare la tabella
                                    clean_command = data.text.replace('\n', ' ').strip()
                                    entries.append({
                                        "source": "PS_Operational.evtx (EID 4104)", 
                                        "command": clean_command, 
                                        "timestamp": ts_str
                                    })
                except Exception:
                    continue
    except Exception as e:
        print(f"[!] Errore critico nel parsing EVTX: {e}")
        
    return entries
    
def parse_ntuser_dat(file_path):
    entries = []
    reg = Registry.Registry(file_path)
    
    # 1. RICERCA DEI TRIGGER (Persistenza nota)
    persistence_keys = [
        r"Software\Microsoft\Windows\CurrentVersion\Run", 
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    ]
    
    for path in persistence_keys:
        try:
            key = reg.open(path)
            ts = format_timestamp(key.timestamp())
            for value in key.values():
                entries.append({"source": f"Persistence Trigger ({value.name()})", "command": str(value.value()), "timestamp": ts})
        except Registry.RegistryKeyNotFoundException: 
            pass
            
    # 2. RICERCA DELLO STORAGE (Payload nascosti fileless)
    # I malware spesso creano sottochiavi in HKCU\Software con nomi casuali
    try:
        software_key = reg.open(r"Software")
        for subkey in software_key.subkeys():
            # Saltiamo le chiavi legittime enormi (es. Microsoft) per velocizzare l'analisi
            if subkey.name() not in ["Microsoft", "Classes", "Policies"]:
                for value in subkey.values():
                    val_data = str(value.value())
                    # Condizione Euristica: se il valore è più lungo di 500 caratteri 
                    # o contiene parole chiave di PowerShell, è un potenziale Storage
                    if len(val_data) > 500 or any(kw in val_data.lower() for kw in ['iex', 'bypass', '-enc', 'powershell']):
                        ts = format_timestamp(subkey.timestamp())
                        entries.append({"source": f"Suspicious Storage ({subkey.name()}\\{value.name()})", "command": val_data, "timestamp": ts})
    except Registry.RegistryKeyNotFoundException: 
        pass

    return entries
    entries = []
    reg = Registry.Registry(file_path)
    
    for path in [r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"]:
        try:
            key = reg.open(path)
            ts = format_timestamp(key.timestamp())
            for value in key.values():
                entries.append({"source": f"Registry ({value.name()})", "command": str(value.value()), "timestamp": ts})
        except Registry.RegistryKeyNotFoundException: 
            pass
            
    try:
        env_key = reg.open(r"Environment")
        ts = format_timestamp(env_key.timestamp())
        for value in env_key.values():
            val_data = str(value.value())
            if len(val_data) > 80 or any(kw in val_data.lower() for kw in ['iex', 'bypass', '-enc', 'powershell']):
                entries.append({"source": f"Environment Var ({value.name()})", "command": val_data, "timestamp": ts})
    except Registry.RegistryKeyNotFoundException: 
        pass

    return entries