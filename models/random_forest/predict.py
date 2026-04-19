import pickle
import pandas as pd
import os, re, sys
import argparse
import hashlib

try:
    from features_engine import extract_features_dict, FEATURE_COLUMNS
except ImportError as e:
    from .features_engine import extract_features_dict, FEATURE_COLUMNS

# ====================================================================
# CONFIGURAZIONI GLOBALI DELL'EDR
# ====================================================================
EDR_THRESHOLD = 50.0  # Soglia per il blocco (50%)

# WHITELIST CRITTOGRAFICA: Inserisci qui l'hash SHA-256 esatto degli script approvati.
TRUSTED_HASHES = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "esempio"
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
def check_whitelist_hash(content, is_verbose=False):
    """Filtro Livello 1: Verifica se il file è matematicamente identico a uno approvato dal SOC."""
    file_hash = calculate_sha256(content)
    
    if is_verbose:
        print(f"[*] DEBUG - Hash SHA-256 del file: {file_hash}")
    
    if file_hash in TRUSTED_HASHES:
        return True, f"Hash SHA-256 approvato dal team IT ({file_hash[:8]}...)"
            
    return False, ""

def is_known_benign(command, origin=""):
    """
    Filtro EDR Livello 1: Whitelist Dinamica Context-Aware.
    Versione ROBUSTA contro apici, backslash e spazi.
    """
    cmd_lower = command.lower().strip()
    cmd_clean = cmd_lower.replace('"', '').replace("'", "")
    
    # --- 1. WHITELIST GIT E SVILUPPO ---
    if cmd_clean.startswith("git ") or cmd_clean.startswith("git.exe"):
        evasion_flags = ['bypass', 'iex', '-enc', 'invoke-', 'hidden', 'powershell']
        if not any(kw in cmd_clean for kw in evasion_flags):
            return True

    # --- 2. WHITELIST DOWNLOADS / DESKTOP ---
    if "downloads" in cmd_clean or "desktop" in cmd_clean:
        if ".exe" in cmd_clean or ".msi" in cmd_clean:
            evasion_flags = ['bypass', 'iex', '-enc', 'invoke-', 'hidden', 'powershell']
            if not any(kw in cmd_clean for kw in evasion_flags):
                return True

    # --- 3. WHITELIST PERCORSI DI SISTEMA ---
    benign_paths = ["c:\\windows\\system32", "c:\\program files", "c:\\program files (x86)"]
    if ".exe" in cmd_clean:
        for path in benign_paths:
            if path in cmd_clean:
                return True

    # --- 4. WHITELIST COMANDI BUILT-IN ---
    if cmd_clean in ["cmd.exe", "explorer.exe", "notepad.exe", "calc.exe"]:
        return True
        
    # --- 5. WHITELIST USERASSIST (Ignora file non eseguibili) ---
    if "UserAssist" in origin:
        if not any(ext in cmd_clean for ext in ['.exe', '.ps1', '.vbs', '.bat', '.cmd']):
            return True

    return False

# ====================================================================
# MODULO 3: MOTORE EURISTICO (Regole di Override)
# ====================================================================
def apply_heuristics(features, base_ml_score):
    edr_score = base_ml_score
    trigger_reasons = []

    if features.get('danger_density', 0) >= 5:
        edr_score += 35
        trigger_reasons.append("Danger Density Critica (>=5)")

    if features.get('critical_ransomware_alert', 0) == 1:
        edr_score = max(edr_score, 95.0)
        trigger_reasons.append("Logica Ransomware Palese")

    if features.get('combo_stealth_exploit', 0) == 1 and features.get('has_web_request', 0) == 1:
        edr_score += 25
        trigger_reasons.append("Combo Stealth + Rete (Possibile Loader)")

    if features.get('critical_evasion_alert', 0) == 1:
        edr_score = max(edr_score, 95.0)
        trigger_reasons.append("Tentativo di Evasione Difese (Bypass AV/AMSI)")

    final_score = min(edr_score, 100.0)
    return final_score, trigger_reasons

# ====================================================================
# MODULO 4: L'API UNICA (Facade Pattern per la GUI)
# ====================================================================
def analyze_single_command(command, origin="", model=None):
    """
    Punto di ingresso UNICO per l'applicazione grafica (app.py) e per il terminale.
    Incapsula Whitelist, Estrazione Feature, ML e Override Euristico.
    """
    clean_cmd = clean_to_single_line(command)
    
    # 1. Controllo Metal Detector (Whitelist Dinamica)
    if is_known_benign(clean_cmd, origin=origin):
        return {
            "is_malicious": False,
            "is_whitelisted": True,
            "score": 0.0,
            "level": "SICURO",
            "reason": "Comando Scartato (Whitelist Dinamica)",
            "features": {},
            "clean_cmd": clean_cmd
        }

    # 2. Validazione Modello
    if model is None:
        raise ValueError("Errore: Modello ML non fornito all'analizzatore.")
        
    # 3. Estrazione Feature
    features = extract_features_dict(clean_cmd)
    f_num = pd.DataFrame([features], columns=FEATURE_COLUMNS).fillna(0).astype(float)
    
    # 4. Predizione ML
    base_ml_score = model.predict_proba(f_num)[0][1] * 100
    
    # 5. Override Euristico
    final_score, trigger_reasons = apply_heuristics(features, base_ml_score)
    
    # 6. Formulazione del Verdetto
    is_malicious = final_score >= EDR_THRESHOLD
    
    if final_score >= 80:
        level = "CRITICO"
    elif final_score >= EDR_THRESHOLD:
        level = "SOSPETTO"
    else:
        level = "SICURO"

    return {
        "is_malicious": is_malicious,
        "is_whitelisted": False,
        "score": final_score,
        "base_ml_score": base_ml_score,
        "level": level,
        "reason": ", ".join(trigger_reasons) if trigger_reasons else "Score assegnato dal Motore ML",
        "features": features,
        "clean_cmd": clean_cmd
    }

# ====================================================================
# MODULO 5: ORCHESTRATORE CLI (Per uso da terminale)
# ====================================================================
def print_report(result_dict, is_whitelisted_hash=False, wl_reason="", is_verbose=False):
    """Funzione di stampa formattata esclusiva per l'uso da terminale (CLI)."""
    print("\n" + "="*70)
    cmd = result_dict.get('clean_cmd', '')
    preview_cmd = cmd if len(cmd) <= 150 else cmd[:150] + "..."
    print(f"COMANDO ANALIZZATO: {preview_cmd}")
    print("-" * 70)

    if is_whitelisted_hash:
        print(">> [ OK: BENIGNO (WHITELIST HASH) ] <<")
        print(f"Motivo: {wl_reason}")
    elif result_dict["is_whitelisted"]:
        print(">> [ OK: BENIGNO (WHITELIST DINAMICA) ] <<")
        print(f"Motivo: {result_dict['reason']}")
    elif result_dict["is_malicious"]:
        print(f">> [ ALLARME ROSSO: BLOCCO EDR - Livello {result_dict['level']} ] <<")
        print(f"Motivi di blocco: {result_dict['reason']}")
        print(f"Punteggio Base ML: {result_dict.get('base_ml_score', 0):.2f}% | Punteggio Finale: {result_dict['score']:.2f}%")
    else:
        print(">> [ OK: BENIGNO ] <<")
        print("Nessuna minaccia rilevata.")
        print(f"Punteggio Base ML: {result_dict.get('base_ml_score', 0):.2f}% | Punteggio Finale: {result_dict['score']:.2f}%")
        
    print("="*70)

    features = result_dict.get("features", {})
    if is_verbose and features:
        print("\n--- DETTAGLI DIAGNOSTICI (--verbose) ---")
        stats_keys = [k for k in features.keys() if not k.startswith('has_') and not k.startswith('api_')]
        print("[Feature Statistiche]")
        for k in stats_keys:
            val = features.get(k, 0)
            if isinstance(val, float): val = round(val, 4)
            print(f"  > {k.ljust(25)}: {val}")
        
        print("\n[Flag Comportamentali Attivati]")
        active_flags = [k for k, v in features.items() if (k.startswith('has_') or k.startswith('api_') or k.startswith('combo_')) and v == 1]        
        if active_flags:
            for flag in active_flags:
                print(f"  > [X] {flag}")
        else:
            print("  > Nessun flag scattato.")
        print("-" * 50 + "\n")

def main():
    parser = argparse.ArgumentParser(description="EDR Agent - Motore Ibrido (ML + Euristiche + Whitelist)")
    parser.add_argument('-f', '--file', type=str, default='input_command.txt', help='Percorso del file contenente lo script')
    parser.add_argument('-v', '--verbose', action='store_true', help='Mostra i dettagli completi')
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[!] File '{args.file}' non trovato.")
        return

    with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # 1. Controllo Whitelist STATICA (Hash) - Si fa solo sul file RAW, quindi vive qui nel main.
    is_whitelisted_hash, wl_reason = check_whitelist_hash(content, args.verbose)
    
    if is_whitelisted_hash:
        print_report({'clean_cmd': clean_to_single_line(content)}, is_whitelisted_hash=True, wl_reason=wl_reason)
        return

    # 2. Se non è nell'hash di sicurezza, passiamo la palla all'API unica
    if args.verbose: print("[*] Caricamento Motore EDR Ibrido...")
    model = load_model()

    if args.verbose: print("[*] Analisi in corso...")
    result = analyze_single_command(content, origin="Terminale CLI", model=model)

    # 3. Stampa a schermo
    print_report(result, is_verbose=args.verbose)

if __name__ == "__main__":
    main()