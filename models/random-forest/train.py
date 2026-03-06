import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate

# --- CONFIGURAZIONE ---
file_input = "../datasets/dataset_features.xlsx" 
n_estimators = 300 
max_depth = 12
k_folds = 3

print("--- TRAINING EDR (100% COMPORTAMENTALE / STATISTICO) ---")

# 1. Caricamento Dati
try:
    df = pd.read_excel(file_input, engine='openpyxl')
    y = df['malicious'].astype(int)
    print(f"[OK] Dataset caricato: {len(df)} righe.")
except Exception as e:
    print(f"[!] Errore caricamento: {e}")
    exit()

# 2. Isolamento Feature Numeriche
print("Preparazione feature numeriche...")
X_numeric = df.drop(columns=['command', 'malicious']).fillna(0).astype(float)
feature_names = X_numeric.columns.tolist()

# 3. Configurazione Modello
rf_model = RandomForestClassifier(
    n_estimators=n_estimators, 
    max_depth=max_depth, 
    min_samples_split=2,   
    min_samples_leaf=1,
    max_features='sqrt',
    class_weight='balanced',
    random_state=42, 
    n_jobs=-1
)
skf = StratifiedKFold(n_splits=k_folds, shuffle=True, random_state=42)

print(f"Esecuzione Cross-Validation su {k_folds} fold...")
scoring = ['accuracy', 'precision', 'recall', 'f1']
cv_results = cross_validate(rf_model, X_numeric, y, cv=skf, scoring=scoring)

# 4. STAMPA DEI RISULTATI
print("\n====================================================")
print(f" RISULTATI PERFORMANCE (SOLO NUMERICO)")
print("====================================================")
print(f"ACCURATEZZA MEDIA: {np.mean(cv_results['test_accuracy']) * 100:.2f}%")
print(f"PRECISION MEDIA:   {np.mean(cv_results['test_precision']) * 100:.2f}%")
print(f"RECALL MEDIA:      {np.mean(cv_results['test_recall']) * 100:.2f}%")
print(f"F1-SCORE MEDIO:    {np.mean(cv_results['test_f1']) * 100:.2f}%")
print("====================================================")

# 5. Addestramento Finale
print("\nAddestramento finale sul 100% dei dati...")
rf_model.fit(X_numeric, y)

# 6. STAMPA DI TUTTE LE FEATURE
importances = pd.DataFrame({
    'Feature': feature_names, 
    'Importanza (%)': rf_model.feature_importances_ * 100
}).sort_values('Importanza (%)', ascending=False)

print("\n--- CLASSIFICA COMPLETA DELLE FEATURE ---")
# Usando solo .to_string() senza .head(), Pandas stamperà tutte le righe
print(importances.to_string(index=False))
print("-----------------------------------------")

# 7. Salvataggio su Disco
with open('modello_powershell_classifier.pkl', 'wb') as f:
    pickle.dump(rf_model, f)

print("[FINITO] Modello Comportamentale salvato correttamente!")