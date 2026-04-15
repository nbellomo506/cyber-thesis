import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack
import time

print("--- AVVIO GRID SEARCH SNELLA ED EFFICACE (Ibrida Num + TF-IDF) ---")

# 1. Caricamento Dataset (dal file Excel finale)
file_input = "../datasets/dataset_features.xlsx"
try:
    print("Lettura del dataset in corso...")
    df = pd.read_excel(file_input, engine='openpyxl')
    df['command'] = df['command'].fillna('').astype(str)
    y = df['malicious'].astype(int)
    print(f"[OK] Dataset caricato: {len(df)} campioni.")
except Exception as e:
    print(f"[!] Errore caricamento: {e}")
    exit()

# 2. Creazione della Matrice Ibrida
print("Preparazione feature numeriche...")
X_numeric = df.drop(columns=['malicious', 'command']).fillna(0).astype(float)

print("Generazione vocabolario TF-IDF (testuale)...")
vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 3), analyzer='char_wb')
X_tfidf = vectorizer.fit_transform(df['command'])

print("Unione matrici (HStack)...")
X_final = hstack([X_numeric.values, X_tfidf])

# 3. Griglia di Ricerca OTTIMIZZATA (Ultra-veloce)
# Tagliamo il "rumore" e concentriamoci sui parametri che fanno davvero la differenza
param_grid = {
    'max_depth': [22, 25, 27, 30],      # Salti più ampi, coprono bene l'area 20-30
    'n_estimators': [100, 300],         # Oltre 300 alberi si spreca solo potenza di calcolo
    'min_samples_split': [2, 3, 4, 5],        # Quanti campioni per dividere un nodo
    'min_samples_leaf': [1, 2],         # Foglie più "pesanti" evitano l'overfitting
    'max_features': ['sqrt'],           # Molto superiore a 'log2' sulle matrici testuali
    'class_weight': ['balanced']        # Veloce ma implacabile sui malware rari
}

# 4. Configurazione
rf = RandomForestClassifier(random_state=42, n_jobs=-1)
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

grid_search = GridSearchCV(
    estimator=rf, 
    param_grid=param_grid, 
    cv=skf, 
    scoring='f1', 
    verbose=2, 
    n_jobs=-1 
)

# 5. Esecuzione
print(f"\nRicerca ottimale in corso su {X_final.shape[1]} feature totali...")
print("-> Combinazioni ridotte per massima efficienza: Veloce e Letale!")
start_time = time.time()
grid_search.fit(X_final, y)
duration = (time.time() - start_time) / 60

# 6. Risultati Finali
print("\n" + "="*50)
print(" RISULTATI OTTIMIZZAZIONE SNELLA")
print("="*50)
print(f"Miglior F1-Score: {grid_search.best_score_ * 100:.2f}%")
print("Parametri Vincenti:")
for param, value in grid_search.best_params_.items():
    print(f" -> {param}: {value}")
print(f"\nTempo di elaborazione: {duration:.2f} minuti")
print("="*50)

# 7. Analisi del Modello Migliore (Feature Importances Mappate)
best_model = grid_search.best_estimator_

# Recuperiamo i nomi delle colonne: Numeriche + Parole del TF-IDF
feature_names = X_numeric.columns.tolist() + vectorizer.get_feature_names_out().tolist()

importances = pd.DataFrame({
    'Feature': feature_names, 
    'Importanza (%)': best_model.feature_importances_ * 100
}).sort_values('Importanza (%)', ascending=False)

print("\n--- TOP 15 FEATURE (Cosa guarda il modello per scovare i malware) ---")
print(importances.head(15).to_string(index=False))