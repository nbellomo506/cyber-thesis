import math
import re
import base64
import pandas as pd

# 1. DEFINIZIONE COLONNE AGGIORNATA
FEATURE_COLUMNS = [
    'length', 'entropy', 'special_chars_ratio', 'upper_case_ratio', 'num_digits', 'longest_word',
    'num_semicolons', 'num_pipes', 'num_backticks', 'num_plus', 'num_dollars', 
    'num_brackets', 'num_quotes', 'num_parenthesis', 'num_commas',
    'has_encoded', 'has_iex', 'has_bypass', 'has_web_request', 'has_dll_ext', 
    'has_api_calls', 'has_add_type', 'has_rundll32', 'has_creds_theft', 'has_persistence',
    'api_getasynckeystate', 'api_setwindowshookex', 'api_virtualalloc', 
    'api_createremotethread', 'has_dllimport', 'has_user32_dll', 'has_keylogging',
    'has_hidden_window', 'combo_bypass_base64',
    
    # --- RANSOMWARE & STEALTH ---
    'has_crypto', 
    'has_destruction',
    'has_vss_purge',
    'has_file_discovery',
    'has_ransom_extension',
    'combo_ransomware_logic',
    'has_reflection',
    'combo_stealth_exploit', # <-- LA NUOVA ARMA
    'danger_density'
]

def calculate_entropy(text):
    if not text or len(text) == 0: return 0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log(p, 2) for p in probs)

def get_longest_word(text):
    words = re.findall(r'\w+', text)
    return max(len(w) for w in words) if words else 0

def decode_ps_base64(command):
    decoded_content = ""
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
    """Smaschera l'offuscamento eliminando i rumori sintattici"""
    text = text.replace("'", "").replace('"', "")
    text = text.replace("+", "").replace("`", "")
    text = re.sub(r'\s+', '', text)
    return text.lower()


def extract_features_dict(command):
    hidden_payload = decode_ps_base64(command)
    if hidden_payload:
        command = command + " " + hidden_payload
    clean_cmd = normalize_command(command)
    
    f = {}
    
    # --- 1. FEATURE STATISTICHE ---
    f['length'] = len(command)
    f['entropy'] = calculate_entropy(command)
    f['special_chars_ratio'] = sum(1 for c in command if not c.isalnum() and not c.isspace()) / len(command) if len(command)>0 else 0
    f['upper_case_ratio'] = sum(1 for c in command if c.isupper()) / len(command) if len(command)>0 else 0
    f['num_digits'] = sum(c.isdigit() for c in command)
    f['longest_word'] = get_longest_word(command)
    f['num_semicolons'] = command.count(';')
    f['num_pipes'] = command.count('|')
    f['num_backticks'] = command.count('`')
    f['num_plus'] = command.count('+')
    f['num_dollars'] = command.count('$')
    f['num_brackets'] = sum(command.count(c) for c in ['[', ']', '{', '}'])
    f['num_quotes'] = command.count("'") + command.count('"')
    f['num_parenthesis'] = command.count('(') + command.count(')')
    f['num_commas'] = command.count(',')
    
    # --- 2. FEATURE COMPORTAMENTALI ---
    f['has_encoded'] = 1 if any(k in clean_cmd for k in ['enc', 'base64', 'encodedcommand']) else 0
    f['has_iex'] = 1 if any(k in clean_cmd for k in ['iex', 'invokeexpression']) else 0
    f['has_bypass'] = 1 if any(k in clean_cmd for k in ['bypass', 'unrestricted']) else 0
    f['has_web_request'] = 1 if any(k in clean_cmd for k in ['http', 'download', 'webclient', 'iwr']) else 0
    f['has_dll_ext'] = 1 if '.dll' in clean_cmd else 0
    f['has_add_type'] = 1 if 'addtype' in clean_cmd else 0
    f['has_rundll32'] = 1 if 'rundll32' in clean_cmd else 0
    
    f['has_api_calls'] = 1 if any(k in clean_cmd for k in [
        'kernel32', 'virtualalloc', 'writeprocessmemory', 'ntdll', 'loadlibrary', 
        'marshal', 'allochglobal', 'getasynckeystate', 'getkeyboardstate', 'setwindowshookex'
    ]) else 0
    f['has_user32_dll'] = 1 if 'user32' in clean_cmd else 0
    f['has_keylogging'] = 1 if any(k in clean_cmd for k in ['getasynckeystate', 'keystate', 'virtualkeycode']) else 0
    
    f['has_creds_theft'] = 1 if any(k in clean_cmd for k in ['mimikatz', 'sekurlsa', 'lsadump', 'creds']) else 0
    f['has_persistence'] = 1 if any(k in clean_cmd for k in ['schtasks', 'scheduledtask', 'setitemproperty']) else 0

    # --- 3. LOGICA RANSOMWARE ---
    f['has_crypto'] = 1 if any(k in clean_cmd for k in ['aesmanaged', 'cryptography', 'transformfinalblock', 'rijndael']) else 0
    f['has_destruction'] = 1 if any(k in clean_cmd for k in ['removeitem', 'writeallbytes', 'delete', 'locked']) else 0
    f['has_vss_purge'] = 1 if any(k in clean_cmd for k in ['vssadmin', 'shadowcopy', 'delete']) else 0
    f['has_file_discovery'] = 1 if any(k in clean_cmd for k in ['getchilditem', 'gci', 'recurse']) else 0
    f['has_ransom_extension'] = 1 if any(k in clean_cmd for k in ['.locked', '.enc', '.crypted', '.aes']) else 0
    f['combo_ransomware_logic'] = 1 if (f['has_file_discovery'] and f['has_crypto'] and f['has_destruction']) else 0

    # --- 4. STEALTH & REFLECTION ---
    f['has_reflection'] = 1 if any(k in clean_cmd for k in ['reflection', 'gettype', 'getfield', 'getmethod', 'nonpublic', 'static']) else 0
    # COMBO STEALTH: Se vedo Reflection + Chiamate API/Keylogging, è un exploit stealth
    f['combo_stealth_exploit'] = 1 if (f['has_reflection'] and (f['has_api_calls'] or f['has_keylogging'])) else 0
    
    f['has_hidden_window'] = 1 if any(k in clean_cmd for k in ['windowstylehidden', 'whidden', 'windowhidden']) else 0
    f['combo_bypass_base64'] = 1 if (f['has_encoded'] and f['has_bypass']) else 0

    # API specifiche
    f['api_getasynckeystate'] = 1 if 'getasynckeystate' in clean_cmd else 0
    f['api_setwindowshookex'] = 1 if 'setwindowshookex' in clean_cmd else 0 
    f['api_virtualalloc'] = 1 if 'virtualalloc' in clean_cmd else 0 
    f['api_createremotethread'] = 1 if 'createremotethread' in clean_cmd else 0 
    f['has_dllimport'] = 1 if 'dllimport' in clean_cmd else 0 
    
    # --- 5. DANGER DENSITY ---
    danger_signals = [c for c in f if c.startswith('has_') or c.startswith('api_') or c.startswith('combo_')]
    f['danger_density'] = sum(f[sig] for sig in danger_signals)
    
    return {col: f.get(col, 0) for col in FEATURE_COLUMNS}