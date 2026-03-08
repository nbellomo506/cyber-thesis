import pandas as pd
import re
from features_engine import extract_features_dict

print("--- GENERAZIONE DATASET ---")

# 1. LETTURA DEL DATASET DI BASE
file_path = "../datasets/dataset_base.xlsx" 

try:
    df = pd.read_excel(file_path, engine='openpyxl') 
    column_name = 'command' 
    print(f"File Excel letto con successo! Trovate {len(df)} righe.")
except Exception as e:
    print(f"[!] Errore di lettura dell'Excel: {e}")
    exit()

# --- PULIZIA OBBLIGATORIA PER IL SALVATAGGIO IN EXCEL ---
ILLEGAL_CHARACTERS_RE = re.compile(r'[\000-\010]|[\013-\014]|[\016-\037]')

def clean_for_excel(text):
    if not isinstance(text, str): return ""
    text = ILLEGAL_CHARACTERS_RE.sub("", text)
    if len(text) > 32000: return text[:32000]
    return text

print("Pulizia dei comandi in corso...")
df[column_name] = df[column_name].apply(clean_for_excel)

# 2. ESTRAZIONE FEATURE
print("Estrazione feature in corso...")
features_list = df[column_name].astype(str).apply(extract_features_dict).tolist()

# 3. CREAZIONE DATAFRAME DELLE FEATURES
df_features = pd.DataFrame(features_list)
df_features['malicious'] = df['malicious']
df_features['command'] = df[column_name]


# 4. SALVATAGGIO IN EXCEL
output_path = "../datasets/dataset_features.xlsx"
print(f"Salvataggio in corso: {output_path} ...")

try:
    df_features.to_excel(output_path, index=False, engine='openpyxl')
    print(f"FINITO! Dataset creato con {len(df_features)} campioni.")
except Exception as e:
    print(f"[!] Errore durante il salvataggio: {e}")