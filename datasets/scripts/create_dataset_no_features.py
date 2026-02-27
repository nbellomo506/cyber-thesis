import os
import pandas as pd
import re

def crea_dataset_bilanciato(cartella_buoni, cartella_cattivi, file_output):
    tutti_i_comandi = []
    
    # Configuriamo le due cartelle e le rispettive label
    sorgenti = [
        (cartella_buoni, 0),
        (cartella_cattivi, 1)
    ]
    
    # Estensioni da cercare
    estensioni = ('.ps1')
    
    for cartella, label in sorgenti:
        print(f"Inizio scansione della cartella: {cartella} (Label assegnata: {label})")
        
        # Cammina attraverso la cartella e le sottocartelle
        for root, dirs, files in os.walk(cartella):
            for file in files:
                if file.lower().endswith(estensioni):
                    path_completo = os.path.join(root, file)
                    
                    try:
                        with open(path_completo, 'r', encoding='utf-8', errors='ignore') as f:
                            for linea in f:
                                linea = linea.strip()
                                
                                # FILTRI DI PULIZIA:
                                if (len(linea) > 10 and 
                                    not linea.startswith('#') and 
                                    not linea.startswith('<#') and
                                    not linea.startswith('REM') and
                                    not linea.isspace()):
                                    
                                    # Aggiungiamo il prefisso powershell.exe se manca
                                    if file.endswith('.ps1') and not linea.lower().startswith('powershell'):
                                        comando_finale = f"powershell.exe -Command \"{linea}\""
                                    else:
                                        comando_finale = linea
                                        
                                    # Invece di una lista semplice, salviamo un dizionario con la label
                                    tutti_i_comandi.append({'command': comando_finale, 'label': label})
                    except Exception as e:
                        print(f"Errore nel leggere {file}: {e}")

    # Creiamo il DataFrame con TUTTI i comandi estratti
    df = pd.DataFrame(tutti_i_comandi)
    
    # Rimuoviamo i duplicati basandoci solo sulla colonna del comando
    df = df.drop_duplicates(subset=['command'])
    
    # --- FASE DI BILANCIAMENTO ---
    count_0 = len(df[df['label'] == 0])
    count_1 = len(df[df['label'] == 1])
    
    print(f"\n--- Estrazione Completata ---")
    print(f"Comandi unici BUONI (0): {count_0}")
    print(f"Comandi unici CATTIVI (1): {count_1}")
    
    # Troviamo il numero minimo per pareggiare
    min_size = min(count_0, count_1)
    
    if min_size == 0:
        print("ERRORE: Una delle due cartelle non ha prodotto comandi validi. Controlla i percorsi.")
        return
        
    print(f"Bilanciamento in corso... Seleziono {min_size} campioni per ogni classe.")
    
    # Estraiamo casualmente 'min_size' righe da entrambe le classi
    df_buoni = df[df['label'] == 0].sample(n=min_size, random_state=42)
    df_cattivi = df[df['label'] == 1].sample(n=min_size, random_state=42)
    
    # Uniamo e mescoliamo le righe (frac=1 mischia il 100% del dataset)
    df_finale = pd.concat([df_buoni, df_cattivi]).sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Salvataggio
    df_finale.to_csv(file_output, index=False, encoding='utf-8')
    print(f"\nSuccesso! Salvato dataset bilanciato con {len(df_finale)} righe in: {file_output}")



# --- ESECUZIONE ---
# Sostituisci i percorsi con le tue cartelle reali
path_buoni = 'C:/Users/nbell/Desktop/mpsd/powershell_benign_dataset/'
path_cattivi = 'C:/Users/nbell/Desktop/mpsd/malicious_pure/' # Esempio di percorso cattivi

# Ho cambiato il nome del file per farti capire che ora è quello globale
crea_dataset_bilanciato(path_buoni, path_cattivi, 'dataset_base_bilanciato.csv')