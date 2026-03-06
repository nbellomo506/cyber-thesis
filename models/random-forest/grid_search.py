import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, StratifiedKFold
import time

print("--- AVVIO GRID SEARCH OTTIMIZZATA (Depth fissata a 27) ---")

# 1. Caricamento Dataset
file_input = "../datasets/dataset_features.csv"
try:
    df = pd.read_csv(file_input, sep=';', decimal=',')
    X = df.drop(columns=['malicious', 'command'])
    y = df['malicious']
    print(f"Dataset caricato: {len(df)} campioni.")
except Exception as e:
    print(f"Errore caricamento: {e}")
    exit()

# 2. Nuova Griglia di Ricerca (Focus sulla qualità della decisione)
# Abbiamo bloccato max_depth a 27 e ora ottimizziamo come l'albero si divide
param_grid = {
    'max_depth': [27],                # Fissato come da tua intuizione
    'n_estimators': [100, 200],       # Testiamo se più alberi aiutano la stabilità
    'min_samples_split': [2, 5, 10],  # Quanti campioni servono per creare una nuova regola
    'min_samples_leaf': [1, 2, 4],    # Quanti campioni devono esserci in una "foglia" finale
    'max_features': ['sqrt', 'log2'], # Quante caratteristiche guardare per ogni bivio
    'class_weight': ['balanced', 'balanced_subsample'] # Fondamentale per EDR: dà più peso ai malware (spesso rari)
}

# 3. Configurazione
rf = RandomForestClassifier(random_state=42, n_jobs=-1)
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

grid_search = GridSearchCV(
    estimator=rf, 
    param_grid=param_grid, 
    cv=skf, 
    scoring='f1', # Cerchiamo il bilanciamento perfetto tra precisione e richiamo
    verbose=2, 
    n_jobs=-1 
)

# 4. Esecuzione
print("Ricerca della configurazione ottimale in corso...")
start_time = time.time()
grid_search.fit(X, y)
duration = (time.time() - start_time) / 60

# 5. Risultati Finali
print("\n" + "="*50)
print(" RISULTATI OTTIMIZZAZIONE (Depth 27)")
print("="*50)
print(f"Miglior F1-Score: {grid_search.best_score_ * 100:.2f}%")
print(f"Parametri Vincenti:")
for param, value in grid_search.best_params_.items():
    print(f" -> {param}: {value}")
print(f"\nTempo di elaborazione: {duration:.2f} minuti")
print("="*50)

# 6. Il Modello Migliore
best_model = grid_search.best_estimator_
importances = pd.DataFrame({
    'Feature': X.columns, 
    'Importanza (%)': best_model.feature_importances_ * 100
}).sort_values('Importanza (%)', ascending=False)

print("\n--- TOP 10 FEATURE (Cosa guarda il modello per scovare i malware) ---")
print(importances.head(10).to_string(index=False))