import pandas as pd
import math
import csv
import re

print("--- ESTRAZIONE FEATURE AVANZATA V3 ---")

file_input = "../datasets/dataset_base.csv" 
file_output = "../datasets/dataset_features.csv"

try:
    df = pd.read_csv(file_input, sep=';')
except Exception as e:
    print(f"Errore di lettura: {e}")
    exit()

df['command'] = df['command'].astype(str)
df['malicious'] = df['malicious'].astype(int)
low_cmd = df['command'].str.lower()

# === FUNZIONI DI SUPPORTO ===
def calculate_entropy(text):
    if not text or len(text) == 0: return 0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log(p, 2) for p in probs)

def get_longest_word(text):
    words = re.findall(r'\w+', text)
    return max(len(w) for w in words) if words else 0

print("Calcolo delle feature in corso...")

# --- 1. FEATURE STRUTTURALI ---
df['length'] = df['command'].apply(len)
df['entropy'] = df['command'].apply(calculate_entropy)
df['special_chars_ratio'] = df['command'].apply(lambda x: sum(1 for c in x if not c.isalnum() and not c.isspace()) / len(x) if len(x)>0 else 0)
df['upper_case_ratio'] = df['command'].apply(lambda x: sum(1 for c in x if c.isupper()) / len(x) if len(x)>0 else 0)
df['num_digits'] = df['command'].apply(lambda x: sum(c.isdigit() for c in x))
df['longest_word'] = df['command'].apply(get_longest_word)

# --- 2. CONTATORI SINTATTICI (SEGNI DI OFFUSCAMENTO) ---
df['num_semicolons'] = df['command'].apply(lambda x: x.count(';'))
df['num_pipes'] = df['command'].apply(lambda x: x.count('|'))
df['num_backticks'] = df['command'].apply(lambda x: x.count('`'))
df['num_plus'] = df['command'].apply(lambda x: x.count('+')) 
df['num_dollars'] = df['command'].apply(lambda x: x.count('$'))
df['num_brackets'] = df['command'].apply(lambda x: sum(x.count(c) for c in ['[', ']', '{', '}']))
df['num_quotes'] = df['command'].apply(lambda x: x.count("'") + x.count('"'))
df['num_parenthesis'] = df['command'].apply(lambda x: x.count('(') + x.count(')'))
df['num_commas'] = df['command'].apply(lambda x: x.count(','))

# --- 3. FEATURE COMPORTAMENTALI & DLL ---
# Offuscamento, Esecuzione e Bypass
df['has_encoded'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['-enc', 'base64', 'encodedcommand']) else 0)
df['has_iex'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['iex', 'invoke-expression', 'i`ex', 'i''ex']) else 0)
df['has_bypass'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['bypass', '-ep', 'unrestricted']) else 0)

# Networking e Download
df['has_web_request'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['http', 'download', 'webclient', 'iwr', 'curl', 'wget']) else 0)

# DLL e API di Sistema (Il tuo punto focale)
df['has_dll_ext'] = low_cmd.apply(lambda x: 1 if '.dll' in x else 0)
df['has_api_calls'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['kernel32', 'virtualalloc', 'writeprocessmemory', 'ntdll', 'user32', 'advapi32', 'loadlibrary']) else 0)
df['has_add_type'] = low_cmd.apply(lambda x: 1 if 'add-type' in x else 0)
df['has_rundll32'] = low_cmd.apply(lambda x: 1 if 'rundll32' in x else 0)

# Credenziali e Persistenza
df['has_creds_theft'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['mimikatz', 'sekurlsa', 'logonpasswords', 'lsadump', 'samdump']) else 0)
df['has_persistence'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['schtasks', 'scheduledtask', 'set-itemproperty', 'new-service']) else 0)

# --- 4. NUOVA: FEATURE DI AGGREGAZIONE (DANGER SCORE) ---
# Questa feature aiuta l'albero a capire la "densità" di sospetti
danger_cols = [col for col in df.columns if col.startswith('has_')]
df['danger_density'] = df[danger_cols].sum(axis=1)

# === SALVATAGGIO ===
print(f"Salvataggio del dataset con {len(df.columns)} colonne...")
df.to_csv(file_output, index=False, sep=';', decimal=',', quoting=csv.QUOTE_ALL)

print(f"\nFINITO! Dataset pronto: {file_output}")