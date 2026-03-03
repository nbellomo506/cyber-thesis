import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate, cross_val_predict
from sklearn.metrics import confusion_matrix
import pickle

# === PARAMETRI OTTIMIZZATI DALLA GRID SEARCH ===
k_folds = 5
n_estimators = 500
max_depth = 30
criterion = 'entropy'  # Risultato della Grid Search
min_samples_leaf = 1
min_samples_split = 2
random_state = 42

print("--- ADDESTRAMENTO MOTORE EDR: POWERSHELL MALWARE CLASSIFIER ---")

# 1. Caricamento Dataset
file_input = "../datasets/dataset_features.csv"
try:
    df = pd.read_csv(file_input, sep=';', decimal=',')
    # Pulizia rapida per sicurezza
    X = df.drop(columns=['malicious', 'command'])
    y = df['malicious']
    print(f"Dataset caricato: {len(df)} righe e {len(X.columns)} feature analizzate.")
except Exception as e:
    print(f"Errore caricamento: {e}")
    exit()

# 2. Configurazione del Modello (Best Params)
rf_model = RandomForestClassifier(
    n_estimators=n_estimators, 
    max_depth=max_depth, 
    criterion=criterion,
    min_samples_leaf=min_samples_leaf,
    min_samples_split=min_samples_split,
    random_state=random_state, 
    n_jobs=-1
)
skf = StratifiedKFold(n_splits=k_folds, shuffle=True, random_state=random_state)

# 3. Validazione Incrociata (K-Fold)
print(f"\nEsecuzione Cross-Validation ({k_folds} fold)...")
scoring = ['accuracy', 'precision', 'recall', 'f1']
cv_results = cross_validate(rf_model, X, y, cv=skf, scoring=scoring)

# 4. Report Prestazioni
print("\n====================================================")
print(f" RISULTATI MEDI VALIDAZIONE")
print("====================================================")
print(f"ACCURATEZZA: {np.mean(cv_results['test_accuracy']) * 100:.2f}%")
print(f"PRECISION:   {np.mean(cv_results['test_precision']) * 100:.2f}% (Capacità di non dare falsi allarmi)")
print(f"RECALL:      {np.mean(cv_results['test_recall']) * 100:.2f}% (Capacità di rilevare malware veri)")
print(f"F1-SCORE:    {np.mean(cv_results['test_f1']) * 100:.2f}%")
print("====================================================")

# 5. Analisi Errori (Matrice di Confusione)
y_pred = cross_val_predict(rf_model, X, y, cv=skf)
cm = confusion_matrix(y, y_pred)

print("\n--- MATRICE DI CONFUSIONE ---")
print(f"Veri Negativi (Benigni OK): {cm[0][0]}")
print(f"Falsi Positivi (Falsi Allarmi): {cm[0][1]}  <-- Da ridurre")
print(f"Falsi Negativi (Malware Persi): {cm[1][0]}  <-- PERICOLOSO")
print(f"Veri Positivi (Malware OK): {cm[1][1]}")

# 6. Addestramento Finale e Feature Importance
print("\nAddestramento finale sul 100% dei dati...")
rf_model.fit(X, y)

importances = pd.DataFrame({
    'Feature': X.columns, 
    'Importanza (%)': rf_model.feature_importances_ * 100
}).sort_values('Importanza (%)', ascending=False)

print("\n--- CLASSIFICA FEATURE ---")
print(importances.to_string(index=False))

# 7. Salvataggio
with open('modello_powershell_classifier.pkl', 'wb') as file:
    pickle.dump(rf_model, file)
print("\n[OK] Modello salvato: 'modello_powershell_classifier.pkl'")