import pickle
import pandas as pd
import os, re, sys
import argparse
import hashlib
from features_engine import extract_features_dict, FEATURE_COLUMNS

# ====================================================================
# CONFIGURAZIONI GLOBALI DELL'EDR
# ====================================================================
EDR_THRESHOLD = 50.0  # Soglia per il blocco (50%)

# WHITELIST CRITTOGRAFICA: Inserisci qui l'hash SHA-256 esatto degli script approvati.
TRUSTED_HASHES = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
]

# ====================================================================
# MODULO 1: CORE E UTILITY
# ====================================================================
def calculate_sha256(content):
    """Calcola l'hash crittografico del file grezzo."""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def clean_to_single_line(text):
    text = text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    return re.sub(r'\s+', ' ', text).strip()

def load_model(model_path='modello_powershell_classifier.pkl'):
    try:
        with open(model_path, 'rb') as f:
            return pickle.load(f)
    except Exception as e:
        print(f"[!] Errore critico: Modello non trovato. ({e})")
        sys.exit(1)

# ====================================================================
# MODULO 2: MOTORE DI WHITELISTING (Fast-Path)
# ====================================================================
def check_whitelist(content, is_verbose=False):
    """Verifica se il file è matematicamente identico a uno approvato dal SOC."""
    file_hash = calculate_sha256(content)
    
    # Stampa l'hash in verbose mode per facilitare l'aggiunta alla whitelist
    if is_verbose:
        print(f"[*] DEBUG - Hash SHA-256 del file: {file_hash}")
    
    if file_hash in TRUSTED_HASHES:
        return True, f"Hash SHA-256 approvato dal team IT ({file_hash[:8]}...)"
            
    return False, ""

# ====================================================================
# MODULO 3: MOTORE EURISTICO (Regole di Override)
# ====================================================================
def apply_heuristics(features, base_ml_score):
    """Applica le regole di ferro dell'EDR per sovrascrivere il ML se necessario."""
    edr_score = base_ml_score
    trigger_reasons = []

    # Regola 1: Danger Density (Troppi flag accesi)
    if features.get('danger_density', 0) >= 5:
        edr_score += 35
        trigger_reasons.append("Danger Density Critica (>=5)")

    # Regola 2: Tolleranza Zero per i Ransomware
    if features.get('critical_ransomware_alert', 0) == 1:
        edr_score = max(edr_score, 95.0)
        trigger_reasons.append("Logica Ransomware Palese")

    # Regola 3: L'Esecuzione Stealth (Es. Mosaic Loader)
    if features.get('combo_stealth_exploit', 0) == 1 and features.get('has_web_request', 0) == 1:
        edr_score += 25
        trigger_reasons.append("Combo Stealth + Rete (Possibile Loader)")

    # Regola 4: Tolleranza Zero per l'Evasione delle Difese (Spegnimento OS Sec)
    if features.get('critical_evasion_alert', 0) == 1:
        edr_score = max(edr_score, 95.0)
        trigger_reasons.append("Tentativo di Evasione Difese (Bypass AV/AMSI)")

    final_score = min(edr_score, 100.0)
    return final_score, trigger_reasons

# ====================================================================
# MODULO 4: MOTORE DI REPORTING
# ====================================================================
def print_report(clean_cmd, is_whitelisted, wl_reason, base_ml, final_score, triggers, features, is_verbose):
    print("\n" + "="*70)
    preview_cmd = clean_cmd if len(clean_cmd) <= 150 else clean_cmd[:150] + "..."
    print(f"COMANDO ANALIZZATO: {preview_cmd}")
    print("-" * 70)

    # Caso 1: Bypass per Whitelist Aziendale
    if is_whitelisted:
        print(">> [ OK: BENIGNO (WHITELIST AZIENDALE) ] <<")
        print(f"Motivo: {wl_reason}")
        print("Analisi ML ed Euristica bypassate. File fidato.")
        
    # Caso 2: Blocco EDR (Maggiore o uguale alla soglia)
    elif final_score >= EDR_THRESHOLD:
        print(">> [ ALLARME ROSSO: BLOCCO EDR ] <<")
        if triggers:
            print("Rilevato da: MOTORE EURISTICO (Override Comportamentale)")
            print(f"Motivi di blocco: {', '.join(triggers)}")
        else:
            print("Rilevato da: MOTORE MACHINE LEARNING")
        print(f"Punteggio Base ML: {base_ml:.2f}% | Punteggio Finale EDR: {final_score:.2f}%")
        
    # Caso 3: File Benigno
    else:
        print(">> [ OK: BENIGNO ] <<")
        print("Nessuna minaccia rilevata.")
        if triggers:
            print(f"Nota: Applicati modificatori euristici ({', '.join(triggers)}), ma sotto soglia.")
        print(f"Punteggio Base ML: {base_ml:.2f}% | Punteggio Finale EDR: {final_score:.2f}%")
        
    print("="*70)

    # --- OUTPUT VERBOSE (DETTAGLI SOTTO IL COFANO) ---
    if is_verbose and not is_whitelisted:
        print("\n--- DETTAGLI DIAGNOSTICI (--verbose) ---")
        
        print("[Feature Statistiche e Conteggi]")
        stats_keys = [k for k in features.keys() if not k.startswith('has_') and not k.startswith('api_')]
        for k in stats_keys:
            val = features.get(k, 0)
            if isinstance(val, float): 
                val = round(val, 4)
            print(f"  > {k.ljust(25)}: {val}")
        
        print("\n[Flag Comportamentali Attivati (Valore = 1)]")
        active_flags = [k for k, v in features.items() if (k.startswith('has_') or k.startswith('api_') or k.startswith('combo_')) and v == 1]        
        if active_flags:
            for flag in active_flags:
                print(f"  > [X] {flag}")
        else:
            print("  > Nessun flag comportamentale è scattato.")
            
        print("-" * 50 + "\n")

# ====================================================================
# MODULO 5: ORCHESTRATORE (MAIN)
# ====================================================================
def main():
    parser = argparse.ArgumentParser(description="EDR Agent - Motore Ibrido (ML + Euristiche + Whitelist)")
    parser.add_argument('-f', '--file', type=str, default='input_command.txt', 
                        help='Percorso del file contenente lo script da analizzare')
    parser.add_argument('-v', '--verbose', action='store_true', 
                        help='Mostra i dettagli completi delle feature estratte e l\'hash')
    args = parser.parse_args()

    path_file = args.file
    is_verbose = args.verbose

    if not os.path.exists(path_file):
        print(f"[!] File '{path_file}' non trovato.")
        return

    # Lettura sicura del contenuto RAW (necessario per l'hash)
    with open(path_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # 1. Linearizzazione per l'analisi e la preview
    clean_cmd = clean_to_single_line(content)
    if not clean_cmd: 
        print("[!] Il file è vuoto o contiene solo spazi.")
        return

    # 2. Controllo Whitelist (Il Fast-Path esce subito se il file è fidato)
    is_whitelisted, wl_reason = check_whitelist(content, is_verbose)
    
    # Variabili di appoggio
    base_ml_score = 0.0
    final_score = 0.0
    trigger_reasons = []
    features = {}

    # 3. Analisi Profonda (Solo se non è in Whitelist)
    if not is_whitelisted:
        if is_verbose:
            print("[*] Caricamento Motore EDR Ibrido...")
        model = load_model()

        if is_verbose:
            print("[*] Estrazione feature in corso...")
            
        features = extract_features_dict(clean_cmd)
        f_num = pd.DataFrame([features], columns=FEATURE_COLUMNS).fillna(0).astype(float)

        # Predizione ML
        prob = model.predict_proba(f_num)[0][1]
        base_ml_score = prob * 100
        
        # Override Euristico
        final_score, trigger_reasons = apply_heuristics(features, base_ml_score)

    # 4. Generazione del Report finale
    print_report(clean_cmd, is_whitelisted, wl_reason, base_ml_score, final_score, trigger_reasons, features, is_verbose)

if __name__ == "__main__":
    main()