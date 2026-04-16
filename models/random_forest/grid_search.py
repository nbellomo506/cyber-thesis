import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.metrics import fbeta_score, make_scorer
import time
import joblib

# Impedisce stampe superflue di avvisi se il dataset è piccolo
import warnings
warnings.filterwarnings('ignore')

print("--- AVVIO GRID SEARCH ORIENTATA AL RECALL (Ottimizzazione F2-Score) ---")

# 1. Caricamento Dataset
file_input = "../datasets/dataset_features.xlsx"
try:
    df = pd.read_excel(file_input, engine='openpyxl')
    y = df['malicious'].astype(int)
    X = df.drop(columns=['malicious', 'command']).fillna(0).astype(float)
    print(f"[OK] Dataset caricato: {len(df)} campioni e {X.shape[1]} feature.")
except Exception as e:
    print(f"[!] Errore: {e}")
    exit()

# 2. Configurazione Scorer F2
f2_scorer = make_scorer(fbeta_score, beta=2)

# 3. Parametri (Griglia ottimizzata per Recall)
param_grid = {
    'n_estimators': [45,46,47,48,49,50,51,52,53,54,55,60],
    
    # Fissiamo i vincitori della scorsa run per coerenza
    'bootstrap': [True],
    'class_weight': [{0: 1, 1: 7}],
    'criterion': ['entropy'],
    'max_depth': [30],
    'max_features': ['sqrt'],
    'max_samples': [None],
    'min_impurity_decrease': [0.0],
    'min_samples_leaf': [1],
    'min_samples_split': [3]
}

# 4. Configurazione Grid Search
rf = RandomForestClassifier(random_state=42, n_jobs=-1)
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

# Calcoliamo quante combinazioni totali verranno provate
n_comb = np.prod([len(v) for v in param_grid.values()])
print(f"[INFO] Saranno testate {n_comb} combinazioni su 5 fold (Totale: {n_comb * 5} fit).")

grid_search = GridSearchCV(
    estimator=rf, 
    param_grid=param_grid, 
    cv=skf, 
    scoring=f2_scorer, 
    verbose=3,  # <--- Aumentato a 3 per vedere il log numerico di ogni fit
    n_jobs=-1 
)

# 5. Esecuzione con monitoraggio tempo
print(f"\nTraining in corso... Monitora l'output qui sotto per l'avanzamento:")
print("-" * 30)
start_time = time.time()

grid_search.fit(X, y)

duration = (time.time() - start_time) / 60

# 6. Risultati Finali
print("\n" + "="*50)
print("OPERAZIONE COMPLETATA")
print(f"Miglior F2-Score: {grid_search.best_score_ * 100:.2f}%")
print(f"Tempo totale: {duration:.2f} min")
print("-" * 50)
print("Parametri Vincenti:")
for param, value in grid_search.best_params_.items():
    print(f" -> {param}: {value}")
print("="*50)

# 7. Salvataggio
best_model = grid_search.best_estimator_
joblib.dump(best_model, 'best_rf_model_f2.pkl')
print("\n[OK] Modello salvato come 'best_rf_model_f2.pkl'")

# 8. Top Feature
importances = pd.DataFrame({
    'Feature': X.columns, 
    'Importanza (%)': best_model.feature_importances_ * 100
}).sort_values('Importanza (%)', ascending=False)

print("\n--- TOP 10 FEATURE COMPORTAMENTALI ---")
print(importances.head(10).to_string(index=False))