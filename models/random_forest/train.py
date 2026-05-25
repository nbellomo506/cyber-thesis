import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# ==========================================
# 1. CONFIGURAZIONE ARCHITETTURALE
# ==========================================
file_input = "../datasets/dataset_features.xlsx" 
bootstrap = True
n_estimators = 55  # Compromesso ottimale tra prestazioni e leggerezza EDR . massimizza recall = 54
max_depth = 30      # Profondità massima per evitare overfitting e garantire decisioni rapide
k_folds = 5         # Standard accademico per la validazione incrociata
min_samples_leaf = 1
min_samples_split = 5
min_impurity_decrease = 0.0
max_samples = None  # Usare il 90% dei dati per ogni albero per mantenere diversità
max_features = 'sqrt'  # Limitiamo le feature per ogni split per aumentare  
class_weight = {0: 1, 1: 7}  # Bilanciamento aggressivo per non perdere i malware
criterion = 'entropy'  # Log Loss ed Entropy sono spesso più penalizzanti dell

print("--- TRAINING EDR: VALIDAZIONE E ADDESTRAMENTO FINALE ---")

# ==========================================
# 2. CARICAMENTO DATI E PREPARAZIONE
# ==========================================
try:
    df = pd.read_excel(file_input, engine='openpyxl')
    y = df['malicious'].astype(int)
    print(f"[OK] Dataset caricato: {len(df)} righe.")
except Exception as e:
    print(f"[!] Errore caricamento: {e}")
    exit()

print("Preparazione feature comportamentali...")
X_numeric = df.drop(columns=['command', 'malicious']).fillna(0).astype(float)
feature_names = X_numeric.columns.tolist()

# Istanza del modello con iperparametri ottimizzati e bilanciamento asimmetrico
rf_model = RandomForestClassifier(
    n_estimators=n_estimators,
    max_depth=max_depth,
    bootstrap=bootstrap,
    class_weight=class_weight,
    criterion=criterion,
    max_samples=max_samples,
    min_samples_leaf=min_samples_leaf,
    min_samples_split=min_samples_split,
    max_features=max_features, 
    min_impurity_decrease=min_impurity_decrease,
    random_state=42
)

# ==========================================
# 3. K-FOLD CROSS-VALIDATION MANUALE (DETTAGLIO MATRICI)
# ==========================================
skf = StratifiedKFold(n_splits=k_folds, shuffle=True, random_state=42)

print("\n====================================================")
print(" RISULTATI DETTAGLIATI PER SINGOLO FOLD (CON MATRICE)")
print("====================================================")

fold_metrics = []
cm_totals = np.zeros((2, 2), dtype=int)

for fold, (train_idx, test_idx) in enumerate(skf.split(X_numeric, y)):
    # Partizionamento dinamico per il fold corrente
    X_train, X_test = X_numeric.iloc[train_idx], X_numeric.iloc[test_idx]
    y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
    
    # Addestramento sul (K-1) e predizione sull'Unseen Data
    rf_model.fit(X_train, y_train)
    y_pred = rf_model.predict(X_test)
    
    # Calcolo Metriche
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    
    # Archiviazione dati per le medie finali
    fold_metrics.append([acc, prec, rec, f1])
    cm_totals += cm 
    
    # Estrazione valori Matrice
    tn, fp, fn, tp = cm.ravel()
    
    print(f"\n--- FOLD {fold + 1} ---")
    print(f"Metriche: Acc {acc*100:.2f}% | Prec {prec*100:.2f}% | Rec {rec*100:.2f}% | F1 {f1*100:.2f}%")
    print(f"Matrice:  TN: {tn:<5} | FP: {fp:<5} | FN: {fn:<5} | TP: {tp:<5}")

# ==========================================
# 4. MEDIE FINALI E MATRICE AGGREGATA
# ==========================================
means = np.mean(fold_metrics, axis=0) * 100

print("\n====================================================")
print(" MEDIE FINALI E MATRICE AGGREGATA (5-FOLD)")
print("====================================================")
print(f"Accuratezza Media: {means[0]:.2f}%")
print(f"Precision Media:   {means[1]:.2f}%")
print(f"Recall Media:      {means[2]:.2f}%")
print(f"F1-Score Medio:    {means[3]:.2f}%")
print("-" * 52)
print(f"                 | Predetto BENIGNO | Predetto MALIGNO")
print(f"-----------------|------------------|-----------------")
print(f"Reale BENIGNO    | {cm_totals[0][0]:<16} | {cm_totals[0][1]:<15} (FP)")
print(f"Reale MALIGNO    | {cm_totals[1][0]:<16} | {cm_totals[1][1]:<15} (TP)")
print("====================================================\n")

# ==========================================
# 5. ADDESTRAMENTO FINALE (100% DEI DATI) E SALVATAGGIO
# ==========================================
print("Addestramento finale definitivo sul 100% dei dati...")
rf_model.fit(X_numeric, y)

importances = pd.DataFrame({
    'Feature': feature_names, 
    'Importanza (%)': rf_model.feature_importances_ * 100
}).sort_values('Importanza (%)', ascending=False)

print("\n--- CLASSIFICA COMPLETA DELLE FEATURE ---")
print(importances.to_string(index=False))
print("-----------------------------------------")

with open('modello_powershell_classifier.pkl', 'wb') as f:
    pickle.dump(rf_model, f)

print("\n[FINITO] Modello serializzato salvato in 'modello_powershell_classifier.pkl'!")