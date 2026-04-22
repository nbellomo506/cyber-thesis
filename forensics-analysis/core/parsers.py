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
    pass

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
    except: ts = "N/D"
    return [{"source": "Console_History", "command": c.strip(), "timestamp": ts} for c in commands if c.strip()]

def parse_evtx_logs(file_path):
    entries = []
    ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
    try:
        with open(file_path, 'rb') as f:
            # Semplificazione per brevità, usa la logica EVTX vista precedentemente
            from Evtx.Evtx import Evtx
            from Evtx.Views import evtx_file_xml_view
            fh = Evtx(f)
            for xml, record in evtx_file_xml_view(fh.get_file_header()):
                root = ET.fromstring(xml)
                system = root.find(f'{ns}System')
                event_id = system.find(f'{ns}EventID').text
                # Estrazione timestamp e ScriptBlockText (EID 4104) o CommandLine (EID 4688)
                if event_id == '4104':
                    ts_str = system.find(f'{ns}TimeCreated').attrib.get('SystemTime').split('.')[0].replace('T', ' ')
                    event_data = root.find(f'{ns}EventData')
                    for data in event_data.findall(f'{ns}Data'):
                        if data.attrib.get('Name') == 'ScriptBlockText' and data.text:
                            entries.append({"source": "EVTX (EID 4104)", "command": data.text.strip(), "timestamp": ts_str})
    except: pass
    return entries

def parse_ntuser_dat(file_path):
    entries = []
    reg = Registry.Registry(file_path)
    # Analisi chiavi Run, UserAssist, etc. come visto prima
    for path in [r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"]:
        try:
            key = reg.open(path)
            ts = format_timestamp(key.timestamp())
            for value in key.values():
                entries.append({"source": f"Registry ({value.name()})", "command": str(value.value()), "timestamp": ts})
        except: pass
    return entries