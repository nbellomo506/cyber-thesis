# file: app.py
import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk
import sys, os

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(parent_dir)

from models.random_forest.predict import analyze_single_command, load_model
from core.acquisition import fetch_history_auto, fetch_registry_standard, extract_via_vss, export_powershell_evtx
from core.parsers import parse_powershell_log, parse_ntuser_dat, parse_evtx_logs

class ForensicApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PowerShell Forensic Analyzer - ML Edition")
        self.geometry("800x750")
        self.model = load_model("../models/random_forest/modello_powershell_classifier.pkl")
        
        self.target_txt = None
        self.target_evtx = None
        self.target_reg = None

        self.setup_ui()

    def setup_ui(self):
        ctk.CTkLabel(self, text="EDR & Forensic Analysis Pipeline", font=("Arial", 22, "bold")).pack(pady=20)

        # --- SEZIONE 1: CRONOLOGIA TESTUALE ---
        self.create_module("1. Cronologia PowerShell (TXT)", 
                           "Nessun file TXT", 
                           self.load_txt_man, 
                           self.fetch_txt_auto)

        # --- SEZIONE 2: EVENTI DI SISTEMA (EVTX) ---
        self.create_module("2. Eventi di Sistema (EVTX)", 
                           "Nessun file EVTX", 
                           self.load_evtx_man, 
                           self.fetch_evtx_auto,
                           warn="Richiede Auditing abilitato (EID 4104/4688)")

        # --- SEZIONE 3: REGISTRO (DAT) ---
        self.create_module("3. Registro di Sistema (NTUSER.DAT)", 
                           "Nessun file DAT", 
                           self.load_reg_man, 
                           self.fetch_reg_auto)

        self.btn_run = ctk.CTkButton(self, text="AVVIA ANALISI INTEGRATA", fg_color="#c0392b", height=50, command=self.run_analysis)
        self.btn_run.pack(pady=30)
        self.lbl_status = ctk.CTkLabel(self, text="Stato: Pronto per l'acquisizione")
        self.lbl_status.pack()

    def create_module(self, title, default_text, cmd_man, cmd_auto, warn=None):
        frame = ctk.CTkFrame(self)
        frame.pack(pady=10, padx=20, fill="x")
        ctk.CTkLabel(frame, text=title, font=("Arial", 14, "bold")).pack(pady=5)
        
        lbl_status = ctk.CTkLabel(frame, text=default_text, text_color="gray")
        lbl_status.pack()
        
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(pady=10)
        ctk.CTkButton(btn_frame, text="Scegli File Manualmente", command=cmd_man).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Acquisisci dal Sistema", fg_color="orange", hover_color="#cc6600", command=cmd_auto).pack(side="left", padx=10)
        
        if warn:
            ctk.CTkLabel(frame, text=f"⚠️ {warn}", font=("Arial", 10, "italic"), text_color="#f1c40f").pack()
        
        # Salviamo il riferimento alla label per aggiornarla
        if "TXT" in title: self.lbl_txt = lbl_status
        elif "EVTX" in title: self.lbl_evtx = lbl_status
        else: self.lbl_reg = lbl_status

    # --- HANDLERS MANUALE ---
    def load_txt_man(self):
        f = filedialog.askopenfilename(filetypes=[("TXT Files", "*.txt")])
        if f: self.target_txt = f; self.lbl_txt.configure(text=os.path.basename(f), text_color="green")
    
    def load_evtx_man(self):
        f = filedialog.askopenfilename(filetypes=[("EVTX Files", "*.evtx")])
        if f: self.target_evtx = f; self.lbl_evtx.configure(text=os.path.basename(f), text_color="green")
    
    def load_reg_man(self):
        f = filedialog.askopenfilename(filetypes=[("DAT Files", "*.dat")])
        if f: self.target_reg = f; self.lbl_reg.configure(text=os.path.basename(f), text_color="green")

    # --- HANDLERS AUTOMATICI ---
    def fetch_txt_auto(self):
        try: self.target_txt = fetch_history_auto(); self.lbl_txt.configure(text="Acquisito (Auto)", text_color="green")
        except Exception as e: messagebox.showerror("Errore", str(e))

    def fetch_evtx_auto(self):
        try: self.target_evtx = export_powershell_evtx(); self.lbl_evtx.configure(text="Esportato (Auto)", text_color="green")
        except Exception as e: messagebox.showerror("Errore Admin", str(e))

    def fetch_reg_auto(self):
        try:
            self.target_reg = fetch_registry_standard()
            self.lbl_reg.configure(text="Acquisito (Standard)", text_color="green")
        except:
            try: self.target_reg = extract_via_vss(); self.lbl_reg.configure(text="Acquisito (VSS)", text_color="green")
            except Exception as e: messagebox.showerror("Errore", str(e))

    def run_analysis(self):
        if not any([self.target_txt, self.target_evtx, self.target_reg]):
            messagebox.showwarning("Vuoto", "Acquisisci almeno un file.")
            return

        findings = []
        # Orchestrazione dei tre parser
        if self.target_txt:
            for e in parse_powershell_log(self.target_txt):
                res = analyze_single_command(e["command"], e["source"], self.model)
                if res["is_malicious"]: findings.append({**e, **res})
        
        if self.target_evtx:
            for e in parse_evtx_logs(self.target_evtx):
                res = analyze_single_command(e["command"], e["source"], self.model)
                if res["is_malicious"]: findings.append({**e, **res})

        if self.target_reg:
            for e in parse_ntuser_dat(self.target_reg):
                res = analyze_single_command(e["command"], e["source"], self.model)
                if res["is_malicious"]: findings.append({**e, **res})

        if findings: self.show_results(findings)
        else: messagebox.showinfo("OK", "Nessun malware trovato.")

    def show_results(self, findings):
        top = ctk.CTkToplevel(self)
        top.title("Analisi Completata")
        top.geometry("1100x500")
        top.attributes("-topmost", True)
        
        cols = ("Data", "Livello", "Score", "Origine", "Comando")
        tree = ttk.Treeview(top, columns=cols, show='headings')
        for c in cols: tree.heading(c, text=c); tree.column(c, width=150, anchor="center")
        tree.column("Comando", width=450, anchor="w")
        tree.pack(fill="both", expand=True, padx=20, pady=20)
        
        tree.tag_configure('critico', foreground='#ff4d4d')
        for f in findings:
            tag = 'critico' if f["level"] == "CRITICO" else ''
            tree.insert("", "end", values=(f["timestamp"], f["level"], f"{f['score']:.2f}%", f["source"], f["command"][:150]), tags=(tag,))

if __name__ == "__main__":
    app = ForensicApp()
    app.mainloop()