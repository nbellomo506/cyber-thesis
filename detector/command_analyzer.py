import argparse
import os
import sys
import base64
import re
from amsi import AMSIEngine

cli_divider = 50
amsi_threshold = 32768  # Soglia di pericolosità AMSI

class MaliciousAnalyzer:
    def __init__(self):
        # Keyword tutte minuscole per facilitare il confronto
        self.suspicious_keywords = ["iex", "-enc", "bypass", "downloadstring", "invoke-expression"]
        self.amsi_checker = AMSIEngine() 

    def extract_and_decode_base64(self, text):
        """Cerca stringhe Base64 tipiche dei payload e le decodifica."""
        # Pattern migliorato per catturare Base64 tipici di PowerShell
        b64_pattern = r'[A-Za-z0-9+/]{30,}={0,2}'
        match = re.search(b64_pattern, text)
        if match:
            try:
                encoded_str = match.group(0)
                # PowerShell usa quasi sempre UTF-16LE per i comandi codificati
                decoded = base64.b64decode(encoded_str).decode('utf-16le', errors='ignore')
                # Se la decodifica non produce testo leggibile, potrebbe essere UTF-8
                if not any(c.isalpha() for c in decoded):
                    decoded = base64.b64decode(encoded_str).decode('utf-8', errors='ignore')
                return decoded
            except:
                pass
        return None

    def analyze_string(self, raw_data):
        findings = {"is_suspicious": False, "reason": [], "score": 0, "decoded_payload": None}
        
        # Semplifichiamo il testo per l'analisi delle keyword
        data_lower = raw_data.lower()

        # 1. DECODIFICA (Facciamola prima per poter analizzare il contenuto nascosto)
        decoded = self.extract_and_decode_base64(raw_data)
        
        # Testo su cui far girare l'euristica (originale + decodificato)
        text_to_check = data_lower
        if decoded:
            findings["decoded_payload"] = decoded
            findings["reason"].append("Rilevato e decodificato payload Base64 nascosto")
            findings["score"] += 20
            text_to_check += " " + decoded.lower()

        # 2. Euristica Locale (ora gira su tutto il testo disponibile)
        for kw in self.suspicious_keywords:
            if kw in text_to_check:
                findings["score"] += 15
                findings["reason"].append(f"Keyword sospetta rilevata: {kw}")

        # 3. Controllo AMSI (Verdetto Autorità)
        # Mandiamo ad AMSI il contenuto decodificato se esiste, perché è quello più "nudo"
        content_to_scan = decoded if decoded else raw_data
        
        amsi_score = self.amsi_checker.scan_string(content_to_scan)
        
        # Se AMSI restituisce 1, potrebbe essere che Defender non riconosca la stringa come virus
        # ma noi abbiamo comunque i risultati della nostra euristica.
        print(f"[DEBUG] Punteggio AMSI: {amsi_score}")
        if amsi_score >= amsi_threshold:  # Soglia da definire in base alla sensibilità desiderata
            findings["is_suspicious"] = True
            findings["score"] += 100
            findings["reason"].append(f"AMSI: Malware confermato (Score: {amsi_score})")
        
        # Soglia di sospetto: se abbiamo trovato keyword o Base64
        if findings["score"] >= 20: 
            findings["is_suspicious"] = True
            
        return findings

# --- LOGICA LINEA DI COMANDO ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analizzatore EDR: Scansiona stringhe da file .txt")
    parser.add_argument("path", help="Percorso del file .txt da analizzare")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"[!] Errore: Il file '{args.path}' non esiste.")
        sys.exit(1)

    try:
        with open(args.path, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read().strip()
    except Exception as e:
        print(f"[!] Errore durante la lettura: {e}")
        sys.exit(1)

    if not content:
        print("[?] Il file è vuoto.")
        sys.exit(0)

    analyzer = MaliciousAnalyzer()
    result = analyzer.analyze_string(content)

    print("\n" + "="*cli_divider)
    print(f" REPORT ANALISI: {args.path}")
    print("="*cli_divider)
    print(f"RISULTATO: {'[!!!] SOSPETTO' if result['is_suspicious'] else '[+] PULITO'}")
    print(f"PUNTEGGIO TOTALE: {result['score']}")
    print("-" * cli_divider)
    
    if result["reason"]:
        print("MOTIVAZIONI:")
        for r in result["reason"]:
            print(f"  - {r}")
    
    if result["decoded_payload"]:
        print("-" * cli_divider)
        print(f"PAYLOAD DECODIFICATO RILEVATO:\n{result['decoded_payload']}")
    
    print("="*cli_divider + "\n")