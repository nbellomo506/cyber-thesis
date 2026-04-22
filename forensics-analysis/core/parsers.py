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
    """Versione corretta e sicura per l'estrazione dai log operativi EVTX con data EU."""
    entries = []
    ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
    
    try:
        # Usiamo il costrutto 'with' nativo per la gestione sicura della memoria
        with Evtx(file_path) as evtx_log:
            for xml, record in evtx_file_xml_view(evtx_log.get_file_header()):
                try:
                    root = ET.fromstring(xml)
                    system = root.find(f'{ns}System')
                    event_id = system.find(f'{ns}EventID').text
                    
                    # Cerchiamo lo Script Block Logging (EID 4104)
                    if event_id == '4104':
                        time_created = system.find(f'{ns}TimeCreated').attrib.get('SystemTime')
                        
                        # Fix per la data in formato Europeo
                        if time_created:
                            try:
                                clean_time = time_created.split('.')[0].replace('Z', '')
                                dt = datetime.strptime(clean_time, "%Y-%m-%dT%H:%M:%S")
                                ts_str = dt.strftime("%d-%m-%Y %H:%M:%S")
                            except Exception:
                                ts_str = "Timestamp Errato"
                        else:
                            ts_str = "N/D"
                        
                        event_data = root.find(f'{ns}EventData')
                        if event_data is not None:
                            for data in event_data.findall(f'{ns}Data'):
                                if data.attrib.get('Name') == 'ScriptBlockText' and data.text:
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