import time
import sys
from register_notifier import start_monitoring

def main():
    print("======================================================")
    print("   PROGETTO TESI: AGENTE EDR (REGISTRY MONITOR)")
    print("   Focus: Rilevamento Malware Fileless")
    print("======================================================")
    print("[*] Inizializzazione moduli...")
    
    # Avvia il monitoraggio definito in register_notifier.py
    start_monitoring()
    
    print("[*] Agente EDR in ascolto. Premere CTRL+C per uscire.")
    print("-" * 54)

    try:
        while True:
            # Mantiene il programma attivo
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Arresto Agente EDR in corso...")
        print("[*] Analisi terminata. Risultati salvati nei log.")
        sys.exit(0)

if __name__ == "__main__":
    main()