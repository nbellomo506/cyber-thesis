import pandas as pd
import re
from features_engine import extract_features_dict

print("--- GENERAZIONE DATASET CON MOTORE CONDIVISO ---")

# 1. LETTURA DEL DATASET DI BASE (DA EXCEL)
# Assicurati che questo sia il nome esatto del tuo file sul computer
file_path = "../datasets/dataset_base.xlsx" 

try:
    # Usiamo read_excel invece di read_csv
    df = pd.read_excel(file_path, engine='openpyxl') 
    
    # Dai file precedenti abbiamo visto che l'intestazione è minuscola
    column_name = 'command' 
    print(f"File Excel letto con successo! Trovate {len(df)} righe.")
    
except Exception as e:
    print(f"[!] Errore di lettura dell'Excel: {e}")
    print("Assicurati che il file si trovi in: ", file_path)
    exit()

# --- PULIZIA OBBLIGATORIA PER IL SALVATAGGIO IN EXCEL ---
# Questa parte è fondamentale: i malware contengono byte nulli (\x00) 
# che mandano in crash openpyxl quando cerchi di salvare il file finale.
ILLEGAL_CHARACTERS_RE = re.compile(r'[\000-\010]|[\013-\014]|[\016-\037]')

def clean_for_excel(text):
    if not isinstance(text, str):
        return ""
    # Rimuove i caratteri binari incompatibili con XML/Excel
    text = ILLEGAL_CHARACTERS_RE.sub("", text)
    
    # Previene il superamento del limite massimo di caratteri per una cella Excel (32.767)
    if len(text) > 32000: 
        return text[:32000]
    return text

print("Pulizia dei comandi dai caratteri binari in corso...")
df[column_name] = df[column_name].apply(clean_for_excel)

# 2. ESTRAZIONE FEATURE
print("Estrazione feature in corso (potrebbe volerci qualche minuto)...")
features_list = df[column_name].astype(str).apply(extract_features_dict).tolist()

# 3. CREAZIONE DATAFRAME DELLE FEATURES
print("Creazione del dataset finale...")
df_features = pd.DataFrame(features_list)

# Aggiungiamo la label (0 o 1) e il comando pulito
df_features['malicious'] = df['malicious']
df_features['command'] = df[column_name]

# 4. SALVATAGGIO IN EXCEL
output_path = "../datasets/dataset_features.xlsx"
print(f"Salvataggio in Excel in corso: {output_path} ...")

try:
    # Salvataggio nel nuovo file Excel
    df_features.to_excel(output_path, index=False, engine='openpyxl')
    print(f"FINITO! Dataset salvato perfettamente in: {output_path}")
except Exception as e:
    print(f"[!] Errore durante il salvataggio in Excel: {e}")