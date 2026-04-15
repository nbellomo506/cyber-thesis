import customtkinter as ctk
from tkinter import filedialog
import pandas as pd
# Importa qui il tuo modello e le tue funzioni di feature engineering
import sys
import os

# 1. Trova il percorso della cartella 'progetto' (la cartella genitore)
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# 2. Aggiungila al sistema così Python vede la cartella 'models'
sys.path.append(parent_dir)

# 3. Ora usa l'import ASSOLUTO (senza punto iniziale)
try:
    from models.random_forest.predict import extract_features_dict, load_model
    print("Moduli caricati con successo!")
except ImportError as e:
    print(f"Errore: {e}")
    
class ForensicApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PowerShell Forensic Analyzer - ML Edition")
        self.geometry("600x450")

        # --- SEZIONE CARICAMENTO ---
        self.label = ctk.CTkLabel(self, text="Seleziona i file per l'analisi Post-Mortem", font=("Arial", 16, "bold"))
        self.label.pack(pady=20)

        # Bottone per Cronologia/Log
        self.btn_log = ctk.CTkButton(self, text="Carica Log PowerShell (txt/evtx)", command=self.load_log)
        self.btn_log.pack(pady=10)

        # Bottone per Registro NTUSER.DAT
        self.btn_reg = ctk.CTkButton(self, text="Carica NTUSER.DAT", command=self.load_registry)
        self.btn_reg.pack(pady=10)

        # Bottone per Dump RAM (Stringhe)
        self.btn_ram = ctk.CTkButton(self, text="Carica Stringhe RAM (txt)", command=self.load_ram)
        self.btn_ram.pack(pady=10)

        # --- BOTTONE AVVIO ---
        self.btn_run = ctk.CTkButton(self, text="AVVIA ANALISI FORENSE", fg_color="red", command=self.run_analysis)
        self.btn_run.pack(pady=30)

        self.status_label = ctk.CTkLabel(self, text="Stato: In attesa di file...")
        self.status_label.pack()

    def load_log(self):
        file = filedialog.askopenfilename()
        print(f"Caricato Log: {file}")

    def load_registry(self):
        file = filedialog.askopenfilename()
        print(f"Caricato Registro: {file}")

    def load_ram(self):
        file = filedialog.askopenfilename()
        print(f"Caricato RAM Dump: {file}")

    def run_analysis(self):
        self.status_label.configure(text="Stato: Analisi in corso con Random Forest...")
        # Qui inseriresti il ciclo che legge i file, estrae le feature e fa il predict
        # Risultato -> Mostra una tabella con i comandi più pericolosi trovati
        print("Analisi completata!")

if __name__ == "__main__":
    app = ForensicApp()
    app.mainloop()