import pickle
import pandas as pd
import os, re, sys
import argparse
from features_engine import extract_features_dict, FEATURE_COLUMNS

def load_model():
    try:
        # Carichiamo SOLO il modello statistico/numerico
        with open('modello_powershell_classifier.pkl', 'rb') as f:
            model = pickle.load(f)
        return model
    except Exception as e:
        print(f"[!] Errore critico: Modello non trovato. ({e})")
        sys.exit(1)

def clean_to_single_line(text):
    text = text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    return re.sub(r'\s+', ' ', text).strip()

def main():
    # --- GESTIONE ARGOMENTI ---
    parser = argparse.ArgumentParser(description="EDR Agent - Solo Machine Learning (Numerico)")
    parser.add_argument('-f', '--file', type=str, default='input_command.txt', 
                        help='Percorso del file contenente lo script da analizzare')
    parser.add_argument('-v', '--verbose', action='store_true', 
                        help='Mostra i dettagli completi delle feature estratte')
    args = parser.parse_args()

    path_file = args.file
    is_verbose = args.verbose

    if not os.path.exists(path_file):
        print(f"[!] File '{path_file}' non trovato.")
        return

    # Lettura sicura
    with open(path_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # 1. Linearizzazione
    clean_cmd = clean_to_single_line(content)
    if not clean_cmd: 
        print("[!] Il file è vuoto o contiene solo spazi.")
        return

    if is_verbose:
        print("[*] Caricamento Motore EDR (Solo ML Comportamentale)...")
        
    model = load_model()

    if is_verbose:
        print("[*] Estrazione feature statistiche in corso...")
        
    # 2. Estrazione Feature
    features = extract_features_dict(clean_cmd)
        
    # 3. Preparazione ML (Puro DataFrame Numerico)
    f_num = pd.DataFrame([features], columns=FEATURE_COLUMNS).fillna(0).astype(float)

    # 4. Predizione 100% Machine Learning
    prob = model.predict_proba(f_num)[0][1]
    
    # --- OUTPUT PRINCIPALE ---
    print("\n" + "="*70)
    preview_cmd = clean_cmd if len(clean_cmd) <= 150 else clean_cmd[:150] + "..."
    print(f"COMANDO ANALIZZATO: {preview_cmd}")
    print("-" * 70)
    
    # Decisione presa esclusivamente dalla probabilità del modello
    if prob > 0.5:
        print(">> [ ALLARME ROSSO: MALEVOLO ] <<")
        print("Rilevato da: MOTORE MACHINE LEARNING (Modello Comportamentale)")
        print(f"Probabilità: {prob*100:.2f}%")
    else:
        print(">> [ OK: BENIGNO ] <<")
        print("Nessuna minaccia rilevata.")
        print(f"Indice di anomalia (ML Score): {prob*100:.2f}%")
        
    print("="*70)

    # --- OUTPUT VERBOSE (DETTAGLI SOTTO IL COFANO) ---
    if is_verbose:
        print("\n--- DETTAGLI DIAGNOSTICI (--verbose) ---")
        
        print("[Feature Statistiche e Conteggi]")
        stats_keys = [k for k in features.keys() if not k.startswith('has_') and not k.startswith('api_')]
        
        for k in stats_keys:
            val = features.get(k, 0)
            if isinstance(val, float): 
                val = round(val, 4)
            print(f"  > {k.ljust(20)}: {val}")
        
        print("\n[Flag Comportamentali Attivati (Valore = 1)]")
        active_flags = [k for k, v in features.items() if (k.startswith('has_') or k.startswith('api_') or k.startswith('combo_')) and v == 1]        
        if active_flags:
            for flag in active_flags:
                print(f"  > [X] {flag}")
        else:
            print("  > Nessun flag comportamentale è scattato.")
            
        print("-" * 50 + "\n")

if __name__ == "__main__":
    main()