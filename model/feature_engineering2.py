import pandas as pd
import math
import csv
import re

print("--- ESTRAZIONE FEATURE AVANZATA ---")

file_input = "../datasets/dataset_base.csv" 
file_output = "../datasets/dataset_features_v2.csv"

try:
    df = pd.read_csv(file_input, sep=';')
except Exception as e:
    print(f"Errore di lettura: {e}")
    exit()

df['command'] = df['command'].astype(str)
df['malicious'] = df['malicious'].astype(int)

# === FUNZIONI DI SUPPORTO ===
def calculate_entropy(text):
    if not text or len(text) == 0: return 0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log(p, 2) for p in probs)

def get_longest_word(text):
    words = text.split()
    return max(len(w) for w in words) if words else 0

print("Calcolo delle feature in corso...")

# --- 1. Feature Strutturali & Complessità ---
df['length'] = df['command'].apply(len)
df['entropy'] = df['command'].apply(calculate_entropy)
# Rapporto caratteri non-alfanumerici (molto alto in script offuscati)
df['special_chars_ratio'] = df['command'].apply(lambda x: sum(1 for c in x if not c.isalnum() and not c.isspace()) / len(x) if len(x)>0 else 0)
df['upper_case_ratio'] = df['command'].apply(lambda x: sum(1 for c in x if c.isupper()) / len(x) if len(x)>0 else 0)
df['longest_word'] = df['command'].apply(get_longest_word)

# --- 2. Feature Sintattiche (I contatori) ---
df['num_semicolons'] = df['command'].apply(lambda x: x.count(';'))
df['num_pipes'] = df['command'].apply(lambda x: x.count('|'))
df['num_backticks'] = df['command'].apply(lambda x: x.count('`'))
df['num_plus'] = df['command'].apply(lambda x: x.count('+')) # Tipico del concatenamento stringhe
df['num_dollars'] = df['command'].apply(lambda x: x.count('$'))
df['num_brackets'] = df['command'].apply(lambda x: sum(x.count(c) for c in ['[', ']', '{', '}']))
df['num_quotes'] = df['command'].apply(lambda x: x.count("'") + x.count('"'))
df['num_parenthesis'] = df['command'].apply(lambda x: x.count('(') + x.count(')'))

# --- 3. Feature Comportamentali (Pattern di attacco) ---
low_cmd = df['command'].str.lower()

# Offuscamento e bypass
df['has_encoded'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['-enc', 'base64', '-e ']) else 0)
df['has_bypass'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['bypass', '-ep', 'unrestricted']) else 0)
df['has_hidden'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['hidden', '-w h', '-windowstyle h']) else 0)
df['has_noprofile'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['-nop', '-noprofile']) else 0)

# Esecuzione e Download
df['has_iex'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['iex', 'invoke-expression', 'i`ex']) else 0)
df['has_web_request'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['http', 'download', 'webclient', 'iwr', 'curl', 'wget']) else 0)

# --- 4. Feature di Sistema (Nuove aggiunte strategiche) ---
# Persistenza e Registro
df['has_registry'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['hklm', 'hkcu', 'set-itemproperty', 'reg ']) else 0)
# WMI (usato per enumerazione e attacchi laterali)
df['has_wmi'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['gwmi', 'get-wmiobject', 'wmic']) else 0)
# Manipolazione tipi e memoria
df['has_type_casting'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['[char]', '[byte[]]', '[convert]', '[system.text.encoding]']) else 0)
# API Win32 (Injection)
df['has_api_calls'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['kernel32', 'virtualalloc', 'writeprocessmemory', 'ntdll']) else 0)

# 1. Evasione (AMSI Bypass e disabilitazione protezioni)
df['has_amsi_bypass'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['amsiutils', 'amsiinitfailed', 'nonpublicfield', 'amsicontext']) else 0)

# 2. Reconnaissance (Chi sono? Cosa c'è in rete?)
df['has_recon'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['whoami', 'net user', 'net group', 'get-ad', 'hostname', 'netstat']) else 0)

# 3. Credential Access (Estrazione password)
df['has_creds_theft'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['sekurlsa', 'logonpasswords', 'lsadump', 'mimikatz', 'get-gpppassword']) else 0)

# 4. Persistence (Rimanere nel sistema)
df['has_persistence'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['scheduledtask', 'schtasks', 'new-service', 'set-service', 'startup']) else 0)

# 5. Reflection (Tecnica avanzata per eseguire codice in memoria senza file)
# Cerca l'uso di [reflect] o l'accesso a metodi privati delle DLL
df['has_reflection'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['[reflect.assembly]', '.getmethod(', '.getfield(', 'nonpublic', 'instance']) else 0)

# 6. Scouting dei processi (Anti-Analisi)
df['has_anti_analysis'] = low_cmd.apply(lambda x: 1 if any(k in x for k in ['get-process', 'stop-process', 'get-service', 'vmware', 'vbox', 'wireshark']) else 0)
# === SALVATAGGIO ===
print(f"Salvataggio del dataset con {len(df.columns)} colonne...")
df.to_csv(file_output, index=False, sep=';', decimal=',', quoting=csv.QUOTE_ALL)

print(f"\nFINITO! Dataset pronto per il Random Forest: {file_output}")