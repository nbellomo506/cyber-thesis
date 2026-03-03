import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, StratifiedKFold
import time

print("--- AVVIO GRID SEARCH PER OTTIMIZZAZIONE EDR ---")

# 1. Caricamento Dataset
file_input = "../datasets/dataset_features_v3.csv"
try:
    # Usiamo lo stesso formato del tuo script precedente
    df = pd.read_csv(file_input, sep=';', decimal=',')
    X = df.drop(columns=['malicious', 'command'])
    y = df['malicious']
    print(f"Dataset caricato: {len(df)} campioni.")
except Exception as e:
    print(f"Errore caricamento: {e}")
    exit()

# 2. Definizione della Griglia (Cosa testiamo?)
param_grid = {
    'n_estimators': [100, 300, 500],      # Quanti alberi "votano"
    'max_depth': [10, 15, 20, 30, None], # La profondità che cercavi
    'min_samples_split': [2, 5, 10],     # Quanti campioni servono per creare un ramo
    'min_samples_leaf': [1, 2, 4],       # Quanti campioni minimi in una foglia
    'criterion': ['gini', 'entropy']     # Metodo per misurare la qualità dello split
}

# 3. Configurazione
rf = RandomForestClassifier(random_state=42, n_jobs=-1)
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

# Usiamo scoring='f1' perché è più affidabile della semplice accuratezza in security
grid_search = GridSearchCV(
    estimator=rf, 
    param_grid=param_grid, 
    cv=skf, 
    scoring='f1', 
    verbose=2, # Ti mostra il progresso dei test
    n_jobs=-1  # Usa tutti i processori del tuo PC
)

# 4. Esecuzione
print("Ricerca in corso... (questo potrebbe richiedere qualche minuto)")
start_time = time.time()
grid_search.fit(X, y)
duration = (time.time() - start_time) / 60

# 5. Risultati Finali
print("\n====================================================")
print(" RISULTATI OTTIMIZZAZIONE")
print("====================================================")
print(f"Miglior F1-Score: {grid_search.best_score_ * 100:.2f}%")
print(f"Migliori Parametri:")
for param, value in grid_search.best_params_.items():
    print(f" -> {param}: {value}")
print(f"\nTempo di elaborazione: {duration:.2f} minuti")
print("====================================================")

# 6. Analisi Feature Importance del Modello Ottimale
best_model = grid_search.best_estimator_
importances = pd.DataFrame({
    'Feature': X.columns, 
    'Importanza (%)': best_model.feature_importances_ * 100
}).sort_values('Importanza (%)', ascending=False)

print("\n--- CLASSIFICA FEATURE (Modello Ottimizzato) ---")
print(importances.head(10).to_string(index=False))