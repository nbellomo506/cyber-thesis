import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import pickle

k_folds = 5
n_estimators = 300
max_depth = 25
random_state = 42

print("--- ADDESTRAMENTO MOTORE EDR (V4 - Con API di Sistema) ---")

# 1. Caricamento Dataset
file_input = "../datasets/dataset_features_v5.csv"
print(f"Caricamento dataset: {file_input}")

try:
    df = pd.read_csv(file_input, sep=';', decimal=',')
except FileNotFoundError:
    print(f"Errore: File {file_input} non trovato. Hai lanciato l'estrazione V4?")
    exit()

# 2. Separazione Feature (X) e Target (y)
# IMPORTANTE: Rimuoviamo il testo del 'command' e la 'label' per lasciare solo i 16 numeri all'IA
X = df.drop(columns=['malicious', 'command'])
y = df['malicious']

print(f"Dataset caricato: {len(df)} righe e {len(X.columns)} feature analizzate.")

# 3. Configurazione del Modello e K-Fold
rf_model = RandomForestClassifier(n_estimators=n_estimators, max_depth=max_depth, random_state=random_state, n_jobs=-1)
skf = StratifiedKFold(n_splits=k_folds, shuffle=True, random_state=42)

# 4. Esecuzione della K-Fold Cross Validation
print(f"\nEsecuzione della {k_folds}-Fold Cross Validation in corso. Attendere...")

scoring = ['accuracy', 'precision', 'recall', 'f1']
cv_results = cross_validate(rf_model, X, y, cv=skf, scoring=scoring)

# 5. Stampa dei Risultati
print("\n====================================================")
print(f" RISULTATI K-FOLD CROSS-VALIDATION (5 Fold)")
print("====================================================")

for i in range(k_folds):
    print(f"Fold {i+1}: Accuratezza {cv_results['test_accuracy'][i] * 100:.2f}%")

print("----------------------------------------------------")
media_accuracy = np.mean(cv_results['test_accuracy']) * 100
std_accuracy = np.std(cv_results['test_accuracy']) * 100
media_precision = np.mean(cv_results['test_precision']) * 100
media_recall = np.mean(cv_results['test_recall']) * 100
media_f1 = np.mean(cv_results['test_f1']) * 100

print(f"ACCURATEZZA MEDIA: {media_accuracy:.2f}% (+/- {std_accuracy:.2f}%)")
print(f"PRECISION MEDIA:   {media_precision:.2f}%")
print(f"RECALL MEDIA:      {media_recall:.2f}%")
print("====================================================")

# 6. Addestramento finale su TUTTI i dati per il salvataggio
print("\nAddestramento del modello finale sul 100% dei dati...")
rf_model.fit(X, y)

# 7. Le Feature Più Importanti (Vediamo se le DLL vincono!)
importances = pd.DataFrame({
    'Feature': X.columns, 
    'Importanza (%)': rf_model.feature_importances_ * 100
}).sort_values('Importanza (%)', ascending=False)

print("\n--- TOP CARATTERISTICHE (Classifica di Importanza) ---")
print(importances.to_string(index=False))

# 8. Salvataggio
with open('modello_powershell_classifier.pkl', 'wb') as file:
    pickle.dump(rf_model, file)
print("\nModello Definitivo salvato come 'modello_powershell_classifier.pkl'!")