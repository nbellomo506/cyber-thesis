import math
import re
import base64

# =====================================================================
# 1. DEFINIZIONE COLONNE (22 Feature)
# =====================================================================
FEATURE_COLUMNS = [
    'entropy_log_length',
    'upper_case_ratio',
    'has_encoded', 'has_iex', 'has_bypass', 'has_web_request', 
    'has_api_calls', 'has_persistence', 'has_hidden_window',
    'has_reflection', 'has_lolbins', 'has_char_code',
    'has_string_manipulation',
    'combo_stealth_exploit', 'combo_bypass_base64',
    'api_virtualalloc', 'api_createremotethread', 'has_dllimport',
    'has_vss_purge', 'combo_ransomware_logic', 'danger_density',
    'critical_ransomware_alert',
    'critical_evasion_alert'
]

# =====================================================================
# 2. FUNZIONI DI SUPPORTO
# =====================================================================
def calculate_entropy(text):
    if not text or len(text) == 0: return 0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log(p, 2) for p in probs)

def decode_ps_base64(command):
    decoded_content = ""
    # Cerca stringhe che sembrano Base64 (almeno 40 caratteri)
    potential_b64 = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', command)
    for b64_str in potential_b64:
        try:
            decoded_bytes = base64.b64decode(b64_str)
            decoded_text = decoded_bytes.decode('utf-16le', errors='ignore')
            if len(decoded_text.strip()) > 5:
                decoded_content += " " + decoded_text
        except: pass
    return decoded_content

def normalize_command(text):
    # 1. NON cancelliamo i commenti. Se il codice è appiattito su una riga, 
    # rimuovere '#' distrugge il payload. Meglio analizzare anche il testo nei commenti.

    # 2. Risolve la frammentazione: "vss" + "admin" -> vssadmin
    text = re.sub(r'["\']\s*\+\s*["\']', '', text)

    # 3. Risolve i [char] code se presenti
    char_matches = re.findall(r'\[char\]\s*(\d+)', text, re.IGNORECASE)
    if char_matches:
        for code in char_matches:
            try:
                text = text.replace(f"[char]{code}", chr(int(code)))
                text = text.replace(f"[char] {code}", chr(int(code)))
            except: pass

    # 4. Pulizia standard: togliamo backticks e apici per compattare le keyword
    text = text.replace("`", "").replace('"', "").replace("'", "")
    
    # 5. Normalizzazione in minuscolo
    return text.lower()
# =====================================================================
# 3. MOTORE DI ESTRAZIONE PRINCIPALE
# =====================================================================
def extract_features_dict(command):
    # Decodifica payload nascosti
    hidden_payload = decode_ps_base64(command)
    full_text = command + " " + hidden_payload if hidden_payload else command
    
    # Crea la versione "pulita" del comando su cui fare il match delle keyword
    clean_cmd = normalize_command(full_text)
    
    f = {}
    length = len(command)
    entropy = calculate_entropy(command)
    
    # --- A. FEATURE STATISTICHE ---
    f['entropy_log_length'] = entropy * math.log(length + 1)
    f['upper_case_ratio'] = sum(1 for c in command if c.isupper()) / length if length > 0 else 0
    
    # --- B. SENSORI COMPORTAMENTALI DI BASE ---
    f['has_encoded'] = 1 if any(k in clean_cmd for k in ['enc', 'base64', 'encodedcommand']) else 0
    f['has_iex'] = 1 if any(k in clean_cmd for k in ['iex', 'invokeexpression']) else 0
    f['has_bypass'] = 1 if any(k in clean_cmd for k in ['bypass', 'unrestricted']) else 0
    f['has_persistence'] = 1 if any(k in clean_cmd for k in ['schtasks', 'scheduledtask', 'setitemproperty', 'new-itemproperty', 'regadd']) else 0
    f['has_hidden_window'] = 1 if any(k in clean_cmd for k in ['windowstylehidden', 'whidden', 'windowhidden', 'showwindow0']) else 0
    
    # Aggiunti: xmlhttp, msxml2 (Mosaic Loader & affini)
    f['has_web_request'] = 1 if any(k in clean_cmd for k in ['http', 'download', 'webclient', 'iwr', 'restmethod', 'bitsadmin', 'certutil', 'xmlhttp', 'msxml2']) else 0

    # Aggiunti: ::load, entrypoint (Esecuzione in memoria avanzata)
    f['has_reflection'] = 1 if any(k in clean_cmd for k in ['reflection', 'gettype', 'getfield', 'getmethod', 'nonpublic', '::load', 'entrypoint']) else 0

    # --- C. EXPLOIT, API & LOLBINS ---
    # Aggiunto: comobject
    f['has_api_calls'] = 1 if any(k in clean_cmd for k in ['kernel32', 'virtualalloc', 'writeprocessmemory', 'ntdll', 'loadlibrary', 'marshal', 'allochglobal', 'getasynckeystate', 'setwindowshookex', 'comobject']) else 0
    f['has_lolbins'] = 1 if any(k in clean_cmd for k in ['bitsadmin', 'certutil', 'mshta', 'regsvr32', 'wmic', 'csc.exe', 'installutil']) else 0
    f['has_char_code'] = 1 if "[char]" in command.lower() else 0
    f['api_virtualalloc'] = 1 if 'virtualalloc' in clean_cmd else 0 
    f['api_createremotethread'] = 1 if 'createremotethread' in clean_cmd else 0 
    f['has_dllimport'] = 1 if 'dllimport' in clean_cmd else 0 
    
    # Rilevamento della frammentazione stringhe (Mosaic Loader)
    # Cerca due stringhe molto corte unite da un + originale (guardando 'command', non 'clean_cmd')
    # Cerca concatenazione sospetta tra stringhe corte OPPURE tra variabili ($var + $var)
    suspicious_concat = re.search(r'(\$\w+\s*\+\s*\$\w+)|(["\']\w{1,3}["\']\s*\+\s*["\']\w{1,3}["\'])', command)
    f['has_string_manipulation'] = 1 if suspicious_concat else 0
    # --- D. COMBINAZIONI LOGICHE ---
    f['combo_stealth_exploit'] = 1 if (f['has_reflection'] and (f['has_api_calls'] or f['has_char_code'])) else 0
    f['combo_bypass_base64'] = 1 if (f['has_encoded'] and f['has_bypass']) else 0
    
    # --- E. LOGICA RANSOMWARE POTENZIATA ---
    has_crypto = 1 if any(k in clean_cmd for k in ['aesmanaged', 'cryptography', 'rijndael', 'createencryptor', 'sha256', 'derivebytes']) else 0
    has_file_mod = 1 if any(k in clean_cmd for k in ['writeallbytes', 'io.file', 'set-content', 'out-file']) else 0
    has_discovery = 1 if any(k in clean_cmd for k in ['getchilditem', 'gci', 'recurse']) else 0
    
    f['has_vss_purge'] = 1 if (any(k in clean_cmd for k in ['vssadmin', 'shadowcopy', 'shadowstorage']) and 'delete' in clean_cmd) else 0
    f['combo_ransomware_logic'] = 1 if (has_crypto and (has_discovery or has_file_mod)) else 0
    
    # Critical Alert: o usa VSSAdmin + Logica Crypto, oppure fa Crypto + Cerca File + Scrive File.
    f['critical_ransomware_alert'] = 1 if (f['has_vss_purge'] and f['combo_ransomware_logic']) or (has_crypto and has_discovery and has_file_mod) else 0
    evasion_keywords = ['mppreference', 'disablerealtime', 'exclusionpath', 'amsiutils', 'amsiinitfailed', 'disableioavprotection']
    
    f['critical_evasion_alert'] = 1 if any(k in clean_cmd for k in evasion_keywords) else 0
    # --- F. DANGER DENSITY (Punteggio Finale EDR) ---
    # Calcola la somma di tutti i flag di pericolo attivi
    danger_signals = [k for k in f if k.startswith('has_') or k.startswith('api_') or k.startswith('combo_') or k.startswith('critical_')]
    f['danger_density'] = sum(f[sig] for sig in danger_signals)
    
    # Ritorna il dizionario assicurandosi che tutte le colonne siano presenti
    return {col: f.get(col, 0) for col in FEATURE_COLUMNS}