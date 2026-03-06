import pickle
import pandas as pd
import os, re, sys
from scipy.sparse import hstack
from features_engine import extract_features_dict, FEATURE_COLUMNS

# Caricamento Modello e Vectorizer
try:
    with open('modello_powershell_classifier.pkl', 'rb') as f:
        model = pickle.load(f)
    with open('vectorizer.pkl', 'rb') as f:
        vectorizer = pickle.load(f)
except Exception as e:
    print(f"[!] Errore caricamento file: {e}")
    sys.exit()

def clean_to_single_line(text):
    text = text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    return re.sub(r'\s+', ' ', text).strip()

def main():
    path_file = "input_command.txt"
    if not os.path.exists(path_file):
        print("[!] File non trovato.")
        return

    with open(path_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Linearizzazione
    clean_cmd = clean_to_single_line(content)
    if not clean_cmd: return

    # 2. Estrazione Ibrida
    f_num = pd.DataFrame([extract_features_dict(clean_cmd)])[FEATURE_COLUMNS]
    f_tfidf = vectorizer.transform([clean_cmd])
    
    # 3. Unione (HStack)
    X_input = hstack([f_num.values, f_tfidf])

    # 4. Predizione
    prob = model.predict_proba(X_input)[0][1]
    
    print("\n" + "="*50)
    print(f"COMANDO: {clean_cmd[:80]}...")
    print("-" * 50)
    print(f"ESITO: {'[!] MALEVOLO' if prob > 0.5 else '[+] BENIGNO'}")
    print(f"SCORE: {prob*100:.2f}%")
    print("="*50 + "\n")

if __name__ == "__main__":
    main()