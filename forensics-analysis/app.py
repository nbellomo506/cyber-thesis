import customtkinter as ctk
from tkinter import filedialog, messagebox
from tkinter import ttk 
import sys
import os

# Setup dei path per importare i moduli custom
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(parent_dir)

# Importiamo la logica di Business (ML, Parsers, Acquisition)
try:
    from models.random_forest.predict import analyze_single_command, load_model
    from core.acquisition import fetch_history_auto, fetch_registry_standard, extract_via_vss
    from core.parsers import parse_powershell_log, parse_ntuser_dat
    print("[OK] Tutti i moduli architetturali caricati.")
except ImportError as e:
    print(f"[!] Errore di architettura: {e}")

class ForensicApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PowerShell Forensic Analyzer - ML Edition")
        self.geometry("700x550")
        
        self.model = None
        try:
            self.model = load_model("../models/random_forest/modello_powershell_classifier.pkl")
        except Exception as e:
            print(f"[!] Errore modello: {e}")
            
        self.target_log_file = None
        self.target_reg_file = None

        self.setup_ui()

    def setup_ui(self):
        """Metodo isolato per la costruzione dell'interfaccia grafica."""
        self.label = ctk.CTkLabel(self, text="Acquisizione Artefatti Post-Mortem", font=("Arial", 18, "bold"))
        self.label.pack(pady=20)

        # Frame LOG
        self.frame_log = ctk.CTkFrame(self)
        self.frame_log.pack(pady=10, padx=20, fill="x")
        ctk.CTkLabel(self.frame_log, text="1. Cronologia / Log PowerShell:", font=("Arial", 14, "bold")).pack(pady=5)
        self.lbl_log_status = ctk.CTkLabel(self.frame_log, text="Nessun file caricato", text_color="gray")
        self.lbl_log_status.pack()
        ctk.CTkButton(self.frame_log, text="Scegli File Manualmente", command=self.load_log).pack(side="left", padx=20, pady=10, expand=True)
        ctk.CTkButton(self.frame_log, text="Preleva dal Sistema (Auto)", fg_color="orange", hover_color="#cc6600", command=self.auto_fetch_history_ui).pack(side="right", padx=20, pady=10, expand=True)

        # Frame REGISTRO
        self.frame_reg = ctk.CTkFrame(self)
        self.frame_reg.pack(pady=10, padx=20, fill="x")
        ctk.CTkLabel(self.frame_reg, text="2. Registro di Sistema (NTUSER.DAT):", font=("Arial", 14, "bold")).pack(pady=5)
        self.lbl_reg_status = ctk.CTkLabel(self.frame_reg, text="Nessun file caricato", text_color="gray")
        self.lbl_reg_status.pack()
        ctk.CTkButton(self.frame_reg, text="Scegli File Manualmente", command=self.load_registry).pack(side="left", padx=20, pady=10, expand=True)
        ctk.CTkButton(self.frame_reg, text="Preleva dal Sistema (Auto)", fg_color="orange", hover_color="#cc6600", command=self.auto_fetch_registry_ui).pack(side="right", padx=20, pady=10, expand=True)

        # Avvio e Stato
        self.btn_run = ctk.CTkButton(self, text="AVVIA ANALISI FORENSE CON RANDOM FOREST", fg_color="red", hover_color="darkred", height=40, command=self.run_analysis)
        self.btn_run.pack(pady=30)
        self.status_label = ctk.CTkLabel(self, text="Stato: In attesa di acquisizione artefatti...")
        self.status_label.pack()

    # --- UI HANDLERS: Acquisizione ---
    def load_log(self):
        file = filedialog.askopenfilename(title="Seleziona Log PowerShell")
        if file:
            self.target_log_file = file
            self.lbl_log_status.configure(text=f"Pronto: {os.path.basename(file)}", text_color="green")

    def load_registry(self):
        file = filedialog.askopenfilename(title="Seleziona NTUSER.DAT")
        if file:
            self.target_reg_file = file
            self.lbl_reg_status.configure(text=f"Pronto: {os.path.basename(file)}", text_color="green")

    def auto_fetch_history_ui(self):
        try:
            self.target_log_file = fetch_history_auto()
            self.lbl_log_status.configure(text="Prelevato in automatico dal sistema!", text_color="green")
        except Exception as e:
            messagebox.showerror("Errore Acquisizione", str(e))

    def auto_fetch_registry_ui(self):
        try:
            # 1. Tenta copia standard
            self.target_reg_file = fetch_registry_standard()
            self.lbl_reg_status.configure(text="NTUSER.DAT acquisito (Standard)!", text_color="green")
        except PermissionError:
            # 2. Se bloccato, tenta VSS
            try:
                self.status_label.configure(text="Stato: Creazione Shadow Copy in corso (VSS)...")
                self.update()
                self.target_reg_file = extract_via_vss()
                self.lbl_reg_status.configure(text="NTUSER.DAT acquisito (VSS)!", text_color="green")
            except PermissionError as pe:
                messagebox.showerror("Privilegi Insufficienti", str(pe))
            except Exception as e:
                messagebox.showerror("Errore VSS", f"Acquisizione VSS fallita: {e}")
        except Exception as e:
            messagebox.showerror("Errore", str(e))
        finally:
            self.status_label.configure(text="Stato: In attesa di acquisizione artefatti...")

    # --- UI HANDLERS: Analisi Orchestration ---
    def run_analysis(self):
        if not self.target_log_file and not self.target_reg_file:
            messagebox.showwarning("Attenzione", "Acquisisci almeno un file.")
            return

        self.status_label.configure(text="Stato: Analisi forense in corso...")
        self.update() 
        malicious_findings = []

        # 1. Analisi Log
        if self.target_log_file:
            try:
                commands = parse_powershell_log(self.target_log_file)
                for cmd in commands:
                    res = analyze_single_command(cmd, origin="Console_History", model=self.model)
                    if res["is_malicious"]:
                        malicious_findings.append({"Comando": cmd, "Score": res["score"], "Livello": res["level"], "Origine": "Console_History"})
            except Exception as e:
                messagebox.showerror("Errore Log", str(e))

        # 2. Analisi Registro
        if self.target_reg_file:
            try:
                entries = parse_ntuser_dat(self.target_reg_file)
                for entry in entries:
                    res = analyze_single_command(entry["command"], origin=entry["source"], model=self.model)
                    if res["is_malicious"]:
                        malicious_findings.append({"Comando": entry["command"], "Score": res["score"], "Livello": res["level"], "Origine": entry["source"]})
            except Exception as e:
                messagebox.showerror("Errore Registro", str(e))

        self.status_label.configure(text="Stato: Analisi completata!")
        
        # 3. Presentazione Risultati
        if malicious_findings:
            malicious_findings = sorted(malicious_findings, key=lambda x: x["Score"], reverse=True)
            self.show_results(malicious_findings)
        else:
            messagebox.showinfo("Risultato", "Nessun comportamento sospetto rilevato!")

    def show_results(self, findings):
        result_window = ctk.CTkToplevel(self)
        result_window.title("Report Analisi Forense")
        result_window.geometry("900x500")
        
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", rowheight=30)
        style.configure("Treeview.Heading", background="#1f538d", foreground="white", font=('Arial', 11, 'bold'))
        style.map('Treeview', background=[('selected', '#1f538d')])

        columns = ("Livello", "Score (%)", "Origine", "Comando")
        tree = ttk.Treeview(result_window, columns=columns, show='headings')
        tree.heading("Livello", text="Livello"); tree.column("Livello", width=100, anchor="center")
        tree.heading("Score (%)", text="Score (%)"); tree.column("Score (%)", width=100, anchor="center")
        tree.heading("Origine", text="Origine"); tree.column("Origine", width=200, anchor="center")
        tree.heading("Comando", text="Payload/Comando"); tree.column("Comando", width=450, anchor="w")
        tree.pack(fill="both", expand=True, padx=20, pady=20)

        tree.tag_configure('critico', foreground='#ff4d4d')
        tree.tag_configure('sospetto', foreground='#ffcc00')

        for item in findings:
            display_cmd = item["Comando"] if len(item["Comando"]) < 150 else item["Comando"][:147] + "..."
            tag = 'critico' if item["Livello"] == "CRITICO" else 'sospetto'
            tree.insert("", "end", values=(item["Livello"], f"{item['Score']:.2f}%", item["Origine"], display_cmd), tags=(tag,))

if __name__ == "__main__":
    app = ForensicApp()
    app.mainloop()