import pandas as pd
import math
import csv

print("--- ESTRAZIONE FEATURE AVANZATA (V5 - L'Arsenale Completo) ---")

file_input = "../datasets/dataset_base_pulito.csv" 
file_output = "../datasets/dataset_features.csv"

print(f"Caricamento del file pulito {file_input} in corso...")
try:
    df = pd.read_csv(file_input, sep=';')
except Exception as e:
    print(f"Errore di lettura: {e}")
    exit()

df['command'] = df['command'].astype(str)
df['malicious'] = df['malicious'].astype(int)

# === FUNZIONI MATEMATICHE ===
def calculate_entropy(text):
    if not text: return 0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log(p, 2) for p in probs)

def get_longest_word(text):
    if not text: return 0
    words = text.split()
    return max(len(w) for w in words) if words else 0

print("Calcolo delle 22 feature in corso. Le nuove CPU stanno lavorando...")

# --- Feature Strutturali Base ---
df['length'] = df['command'].apply(len)
df['entropy'] = df['command'].apply(calculate_entropy)
df['special_chars_ratio'] = df['command'].apply(lambda x: sum(1 for c in x if not c.isalnum() and not c.isspace()) / len(x) if len(x)>0 else 0)
df['longest_word'] = df['command'].apply(get_longest_word)

# --- Feature Strutturali Avanzate (I contatori) ---
df['num_semicolons'] = df['command'].apply(lambda x: x.count(';'))
df['num_pipes'] = df['command'].apply(lambda x: x.count('|'))
df['num_backticks'] = df['command'].apply(lambda x: x.count('`'))
df['num_plus'] = df['command'].apply(lambda x: x.count('+'))
df['num_dollars'] = df['command'].apply(lambda x: x.count('$'))
# NUOVE STRUTTURALI
df['num_brackets'] = df['command'].apply(lambda x: sum(x.count(c) for c in ['[', ']', '{', '}']))
df['num_quotes'] = df['command'].apply(lambda x: x.count("'") + x.count('"'))

# --- Feature Comportamentali (Parole chiave e flag) ---
df['has_encoded'] = df['command'].str.lower().apply(lambda x: 1 if any(k in x for k in ['-enc', 'base64']) else 0)
df['has_web_request'] = df['command'].str.lower().apply(lambda x: 1 if any(k in x for k in ['http', 'download', 'net.webclient', 'iwr']) else 0)
df['has_hidden_window'] = df['command'].str.lower().apply(lambda x: 1 if any(k in x for k in ['hidden', '-w h', '-windowstyle h']) else 0)
df['has_bypass'] = df['command'].str.lower().apply(lambda x: 1 if any(k in x for k in ['bypass', '-ep bypass', 'unrestricted']) else 0)
# NUOVE COMPORTAMENTALI
df['has_noprofile'] = df['command'].str.lower().apply(lambda x: 1 if any(k in x for k in ['-nop', '-noprofile']) else 0)
df['has_iex'] = df['command'].str.lower().apply(lambda x: 1 if any(k in x for k in ['iex', 'invoke-expression']) else 0)

# --- Feature Evasive (Compressione e Type Casting) ---
# NUOVE EVASIVE
df['has_compression'] = df['command'].str.lower().apply(lambda x: 1 if any(k in x for k in ['deflatestream', 'gzipstream', 'compression']) else 0)
df['has_char_byte'] = df['command'].str.lower().apply(lambda x: 1 if any(k in x for k in ['[char]', '[byte[]]', '[convert]']) else 0)

# --- Feature API di Sistema (Process Injection) ---
df['has_system_dll'] = df['command'].str.lower().apply(lambda x: 1 if any(k in x for k in ['kernel32', 'ntdll', 'user32', 'advapi32']) else 0)
df['has_dll_import'] = df['command'].str.lower().apply(lambda x: 1 if any(k in x for k in ['dllimport', 'loadlibrary', 'getprocaddress']) else 0)
df['has_injection_api'] = df['command'].str.lower().apply(lambda x: 1 if any(k in x for k in ['virtualalloc', 'writeprocessmemory', 'createremotethread']) else 0)

# === SALVATAGGIO ===
print("Salvataggio del dataset con le nuove feature...")
df.to_csv(
    file_output, 
    index=False, 
    sep=';', 
    decimal=',', 
    quoting=csv.QUOTE_ALL
)

print(f"\nFINITO! Il super-dataset è salvato come: {file_output}")