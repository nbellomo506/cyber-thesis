import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import StratifiedKFold, cross_validate
from scipy.sparse import hstack
from features_engine import extract_features_dict, FEATURE_COLUMNS

# --- CONFIGURAZIONE ---
file_input = "../datasets/dataset_features.csv"
n_estimators = 500
max_depth = 27
k_folds = 5

print("--- TRAINING EDR V5 (IBRIDO: NUMERICO + TF-IDF) ---")

# 1. Caricamento Dati
try:
    df = pd.read_csv(file_input, sep=';')
    df['command'] = df['command'].astype(str)
    y = df['malicious']
    print(f"[OK] Dataset caricato: {len(df)} righe.")
except Exception as e:
    print(f"[!] Errore caricamento: {e}")
    exit()

# 2. Estrazione Feature Numeriche (dal tuo motore)
print("Estrazione feature numeriche in corso...")
X_numeric = pd.DataFrame([extract_features_dict(c) for c in df['command']])

# 3. Vettorizzazione TF-IDF (Analisi del vocabolario)
print("Generazione vocabolario TF-IDF (NGrams 1-3)...")
vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 3), analyzer='char_wb')
X_tfidf = vectorizer.fit_transform(df['command'])

# 4. Unione delle Feature (HStack)
# Uniamo la matrice densa (numerica) con quella sparsa (TF-IDF)
X_final = hstack([X_numeric.values, X_tfidf])

# 5. Configurazione Modello e Cross-Validation
rf_model = RandomForestClassifier(
    n_estimators=n_estimators, 
    max_depth=max_depth, 
    random_state=42, 
    n_jobs=-1
)
skf = StratifiedKFold(n_splits=k_folds, shuffle=True, random_state=42)

print(f"Esecuzione Cross-Validation su {k_folds} fold...")
scoring = ['accuracy', 'precision', 'recall', 'f1']
cv_results = cross_validate(rf_model, X_final, y, cv=skf, scoring=scoring)

# 6. STAMPA DEI RISULTATI
print("\n====================================================")
print(f" RISULTATI PERFORMANCE (IBRIDO)")
print("====================================================")
print(f"ACCURATEZZA MEDIA: {np.mean(cv_results['test_accuracy']) * 100:.2f}%")
print(f"PRECISION MEDIA:   {np.mean(cv_results['test_precision']) * 100:.2f}%")
print(f"RECALL MEDIA:      {np.mean(cv_results['test_recall']) * 100:.2f}%")
print(f"F1-SCORE MEDIO:    {np.mean(cv_results['test_f1']) * 100:.2f}%")
print("====================================================")

# 7. Addestramento Finale e Salvataggio
print("\nAddestramento finale sul 100% dei dati...")
rf_model.fit(X_final, y)

with open('modello_powershell_classifier.pkl', 'wb') as f:
    pickle.dump(rf_model, f)
with open('vectorizer.pkl', 'wb') as f:
    pickle.dump(vectorizer, f)

print("\n[FINITO] Modello e Vectorizer salvati correttamente!")