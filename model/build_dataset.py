import pandas as pd
import csv
from features_engine import extract_features_dict

print("--- GENERAZIONE DATASET CON MOTORE CONDIVISO ---")
df = pd.read_csv("../datasets/dataset_base.csv", sep=';')

# Applichiamo la funzione a tutto il dataset
print("Estrazione feature in corso...")
features_list = df['command'].astype(str).apply(extract_features_dict).tolist()

# Creiamo un nuovo dataframe con le feature e la label
df_features = pd.DataFrame(features_list)
df_features['malicious'] = df['malicious']
df_features['command'] = df['command'] # Opzionale, per debug

df_features.to_csv("../datasets/dataset_features.csv", index=False, sep=';', decimal=',', quoting=csv.QUOTE_ALL)
print("FINITO! Dataset salvato.")