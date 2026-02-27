import pandas as pd
import math

# 1. Funzione matematica per l'entropia
def calculate_entropy(text):
    if not text:
        return 0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log(p, 2) for p in probs)

# 2. Funzione principale per trasformare il DataFrame
def extract_features(df):
    print("Calcolo lunghezza e entropia...")
    df['command'] = df['command'].astype(str)
    
    df['length'] = df['command'].apply(len)
    df['entropy'] = df['command'].apply(calculate_entropy)
    
    # Rapporto caratteri speciali (es. se la stringa è lunga 100 e ha 20 virgole, il rapporto è 0.2)
    def special_ratio(text):
        if not text: return 0
        special_count = sum(1 for c in text if not c.isalnum() and not c.isspace())
        return special_count / len(text)
    
    df['special_chars_ratio'] = df['command'].apply(special_ratio)
    
    # Keyword analysis (0 o 1)
    df['has_encoded'] = df['command'].str.lower().apply(
        lambda x: 1 if any(k in x for k in ['-enc', 'base64', 'frombase64']) else 0
    )
    df['has_web_request'] = df['command'].str.lower().apply(
        lambda x: 1 if any(k in x for k in ['http', 'download', 'iwr', 'webclient']) else 0
    )
    
    df['num_semicolons'] = df['command'].apply(lambda x: x.count(';'))
    df['num_pipes'] = df['command'].apply(lambda x: x.count('|'))
    
    return df

# --- ESECUZIONE ---
input_file = "dataset_base_bilanciato.csv" # Il file generato dallo step precedente
output_file = "dataset_features.csv" # Il file finale per il Machine Learning

print(f"Caricamento file {input_file}...")
df_grezzo = pd.read_csv(input_file)

print("Inizio estrazione feature (attendere)...")
df_elaborato = extract_features(df_grezzo)

# Salviamo il file CSV con tutte le feature calcolate
df_elaborato.to_csv(output_file, index=False)

print(f"Finito! Dataset matematico salvato in: {output_file}")
print("\nPrime 5 righe delle feature estratte:")
print(df_elaborato[['length', 'entropy', 'special_chars_ratio', 'label']].head())