# file: app.py
import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk
import sys
import os
import threading
from datetime import datetime

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(parent_dir)

from models.random_forest.predict import analyze_single_command, load_model
from core.acquisition import fetch_history_auto, fetch_registry_standard, extract_via_vss, export_powershell_evtx
from core.parsers import parse_powershell_log, parse_ntuser_dat, parse_evtx_logs

class ForensicApp(ctk.CTk):

    description = """Carica i file da analizzare tramite l'interfaccia sottostante altrimenti acquisiscili automaticamente.
Non è necessario caricare tutti gli artefatti per avviare l'analisi forense.
L'analisi integrata combinerà i risultati di tutti i file caricati, evidenziando eventuali comandi sospetti o malevoli.
Potrebbe essere necessario qualche minuto per completare l'analisi, a seconda della quantità di dati."""
    
    title_text = "PowerShell Commands Forensic Analyzer"

    def __init__(self):
        super().__init__()
        self.title("PowerShell Forensic Analyzer - ML Edition")
        self.geometry("850x650")
        self.model = load_model("../models/random_forest/modello_powershell_classifier.pkl")
        
        self.target_txt = None
        self.target_evtx = None
        self.target_reg = None
        self.ui_buttons = []

        self.setup_ui()
        self.setup_loader() 

    def setup_ui(self):
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(self.main_container, text=self.title_text, font=("Arial", 22, "bold")).pack(pady=(0, 10))
        ctk.CTkLabel(self.main_container, text=self.description, font=("Arial", 12, "italic")).pack(pady=(0, 20))

        # --- CREAZIONE DELLA TABELLA DI ACQUISIZIONE ---
        self.build_acquisition_table()

        # --- TASTO ANALISI ---
        self.btn_run = ctk.CTkButton(self.main_container, text="AVVIA ANALISI INTEGRATA", fg_color="#c0392b", height=50, font=("Arial", 14, "bold"), command=self.run_analysis)
        self.btn_run.pack(pady=(20, 15))

    def build_acquisition_table(self):
        table_frame = ctk.CTkFrame(self.main_container)
        table_frame.pack(fill="x", pady=10)

        table_frame.grid_columnconfigure(0, weight=3) 
        table_frame.grid_columnconfigure(1, weight=3) 
        table_frame.grid_columnconfigure(2, weight=1) 
        table_frame.grid_columnconfigure(3, weight=1) 

        # --- INTESTAZIONI ---
        headers = ["Artefatto Forense", "Stato Attuale", "Azione Manuale", "Azione Automatica"]
        for col, text in enumerate(headers):
            ctk.CTkLabel(table_frame, text=text, font=("Arial", 13, "bold"), text_color="#aaaaaa").grid(row=0, column=col, padx=10, pady=(15, 10), sticky="w" if col < 2 else "")

        separator = ctk.CTkFrame(table_frame, height=2, fg_color="#333333")
        separator.grid(row=1, column=0, columnspan=4, sticky="ew", padx=10, pady=(0, 10))

        # --- RIGA 1: TXT ---
        ctk.CTkLabel(table_frame, text="1. Cronologia PowerShell (TXT)", font=("Arial", 13, "bold")).grid(row=2, column=0, padx=10, pady=10, sticky="w")
        self.lbl_txt = ctk.CTkLabel(table_frame, text="Nessun file", text_color="gray")
        self.lbl_txt.grid(row=2, column=1, padx=10, pady=10, sticky="w")
        
        btn_txt_man = ctk.CTkButton(table_frame, text="Sfoglia...", width=100, command=self.load_txt_man)
        btn_txt_man.grid(row=2, column=2, padx=10, pady=10)
        btn_txt_auto = ctk.CTkButton(table_frame, text="Acquisisci", width=100, fg_color="orange", hover_color="#cc6600", command=self.fetch_txt_auto)
        btn_txt_auto.grid(row=2, column=3, padx=10, pady=10)

        # --- RIGA 2: EVTX ---
        evtx_title = "2. Eventi di Sistema (EVTX)\n(Richiede Auditing EID 4104)"
        ctk.CTkLabel(table_frame, text=evtx_title, font=("Arial", 13, "bold"), justify="left").grid(row=3, column=0, padx=10, pady=10, sticky="w")
        self.lbl_evtx = ctk.CTkLabel(table_frame, text="Nessun file", text_color="gray")
        self.lbl_evtx.grid(row=3, column=1, padx=10, pady=10, sticky="w")
        
        btn_evtx_man = ctk.CTkButton(table_frame, text="Sfoglia...", width=100, command=self.load_evtx_man)
        btn_evtx_man.grid(row=3, column=2, padx=10, pady=10)
        btn_evtx_auto = ctk.CTkButton(table_frame, text="Esporta", width=100, fg_color="orange", hover_color="#cc6600", command=self.fetch_evtx_auto)
        btn_evtx_auto.grid(row=3, column=3, padx=10, pady=10)

        # --- RIGA 3: REGISTRO ---
        ctk.CTkLabel(table_frame, text="3. Registro (NTUSER.DAT)", font=("Arial", 13, "bold")).grid(row=4, column=0, padx=10, pady=10, sticky="w")
        self.lbl_reg = ctk.CTkLabel(table_frame, text="Nessun file", text_color="gray")
        self.lbl_reg.grid(row=4, column=1, padx=10, pady=10, sticky="w")
        
        btn_reg_man = ctk.CTkButton(table_frame, text="Sfoglia...", width=100, command=self.load_reg_man)
        btn_reg_man.grid(row=4, column=2, padx=10, pady=10)
        btn_reg_auto = ctk.CTkButton(table_frame, text="Estrai", width=100, fg_color="orange", hover_color="#cc6600", command=self.fetch_reg_auto)
        btn_reg_auto.grid(row=4, column=3, padx=10, pady=10)

        # --- RIGA 4: SEPARATORE ---
        separator2 = ctk.CTkFrame(table_frame, height=2, fg_color="#333333")
        separator2.grid(row=5, column=0, columnspan=4, sticky="ew", padx=10, pady=10)

        # --- RIGA 5: ACQUISIZIONE MASSIVA ---
        ctk.CTkLabel(table_frame, text="⚡ Acquisizione Massiva", font=("Arial", 13, "bold"), text_color="#d35400").grid(row=6, column=0, padx=10, pady=(0, 15), sticky="w")
        
        self.btn_fetch_all = ctk.CTkButton(table_frame, text="ESTRAI TUTTO", fg_color="#d35400", hover_color="#e67e22", font=("Arial", 12, "bold"), command=self.fetch_all_auto)
        self.btn_fetch_all.grid(row=6, column=2, columnspan=2, padx=10, pady=(0, 15), sticky="ew")

        # --- RIGA 6: BARRA DI STATO (INTEGRATA IN TABELLA) ---
        self.lbl_status = ctk.CTkLabel(table_frame, text="Stato: Pronto per l'acquisizione", font=("Arial", 12, "italic"), text_color="gray")
        self.lbl_status.grid(row=7, column=0, columnspan=4, pady=(0, 15), sticky="")
        # Aggiungiamo tutti i bottoni alla lista per bloccarli durante i caricamenti
        self.ui_buttons.extend([btn_txt_man, btn_txt_auto, btn_evtx_man, btn_evtx_auto, btn_reg_man, btn_reg_auto, self.btn_fetch_all])

    # --- MOTORE DI OVERLAY (SCHERMO INTERO) ---
    def setup_loader(self):
        self.loader_frame = ctk.CTkFrame(self, fg_color="#0d0d0d", corner_radius=0)
        
        self.loader_label = ctk.CTkLabel(self.loader_frame, text="", font=("Consolas", 22, "bold"), text_color="#f1c40f")
        self.loader_label.place(relx=0.5, rely=0.5, anchor="center")
        
        self.loader_sublabel = ctk.CTkLabel(self.loader_frame, text="Attendere...", font=("Arial", 12, "italic"), text_color="#aaaaaa")
        self.loader_sublabel.place(relx=0.5, rely=0.56, anchor="center")

    def show_loader(self, message):
        self.loader_label.configure(text=f"⏳ {message}")
        self.loader_frame.place(relx=0, rely=0, relwidth=1.0, relheight=1.0)
        self.update_idletasks()

    def hide_loader(self):
        self.loader_frame.place_forget()

    def run_in_background(self, message, target_func, callback):
        self.show_loader(message)
        
        def task():
            result, error = None, None
            try:
                result = target_func()
            except Exception as e:
                error = str(e)
            self.after(0, lambda: callback(result, error))
            
        threading.Thread(target=task, daemon=True).start()

    # --- HANDLERS MANUALE ---
    def load_txt_man(self):
        f = filedialog.askopenfilename(filetypes=[("TXT Files", "*.txt")])
        if f: 
            self.show_loader("Caricamento TXT in corso...")
            def finish():
                self.target_txt = f
                self.lbl_txt.configure(text=os.path.basename(f)[:25] + "...", text_color="green")
                self.hide_loader()
            self.after(300, finish)
    
    def load_evtx_man(self):
        f = filedialog.askopenfilename(filetypes=[("EVTX Files", "*.evtx")])
        if f:
            self.show_loader("Caricamento EVTX in corso...")
            def finish():
                self.target_evtx = f
                self.lbl_evtx.configure(text=os.path.basename(f)[:25] + "...", text_color="green")
                self.hide_loader()
            self.after(300, finish)
    
    def load_reg_man(self):
        f = filedialog.askopenfilename(filetypes=[("DAT Files", "*.dat")])
        if f:
            self.show_loader("Caricamento Registro in corso...")
            def finish():
                self.target_reg = f
                self.lbl_reg.configure(text=os.path.basename(f)[:25] + "...", text_color="green")
                self.hide_loader()
            self.after(300, finish)

    # --- HANDLERS AUTOMATICI SINGOLI ---
    def fetch_txt_auto(self):
        def cb(res, err):
            self.hide_loader()
            if err: messagebox.showerror("Errore", err)
            else: 
                self.target_txt = res
                self.lbl_txt.configure(text="Acquisito (Auto)", text_color="green")
        self.run_in_background("Acquisizione Cronologia (TXT)...", fetch_history_auto, cb)

    def fetch_evtx_auto(self):
        def cb(res, err):
            self.hide_loader()
            if err: messagebox.showerror("Errore Admin", err)
            else:
                self.target_evtx = res
                self.lbl_evtx.configure(text="Esportato (Auto)", text_color="green")
        self.run_in_background("Estrazione log operativi EVTX in corso...", export_powershell_evtx, cb)

    def fetch_reg_auto(self):
        def _do_reg_fetch():
            try: return fetch_registry_standard(), "Standard"
            except: return extract_via_vss(), "VSS"
            
        def cb(res, err):
            self.hide_loader()
            if err: messagebox.showerror("Errore", err)
            else:
                self.target_reg = res[0]
                self.lbl_reg.configure(text=f"Acquisito ({res[1]})", text_color="green")
        self.run_in_background("Acquisizione Hive di Registro in corso...", _do_reg_fetch, cb)

    # --- NUOVO HANDLER MASSIVO (ALL IN ONE) ---
    def fetch_all_auto(self):
        def _do_fetch_all():
            results = {}
            try: results['txt'] = fetch_history_auto()
            except Exception as e: results['txt_err'] = str(e)
            
            try: results['evtx'] = export_powershell_evtx()
            except Exception as e: results['evtx_err'] = str(e)
            
            try: results['reg'] = fetch_registry_standard()
            except:
                try: results['reg'] = extract_via_vss()
                except Exception as e: results['reg_err'] = str(e)
                
            return results

        def cb(res, err):
            self.hide_loader()
            if err:
                messagebox.showerror("Errore Imprevisto", err)
                return
            
            errors_found = False
            
            if 'txt' in res:
                self.target_txt = res['txt']
                self.lbl_txt.configure(text="Acquisito (Auto)", text_color="green")
            elif 'txt_err' in res:
                self.lbl_txt.configure(text="Errore Acquisizione", text_color="red")
                errors_found = True
                
            if 'evtx' in res:
                self.target_evtx = res['evtx']
                self.lbl_evtx.configure(text="Esportato (Auto)", text_color="green")
            elif 'evtx_err' in res:
                self.lbl_evtx.configure(text="Errore (Mancano Privilegi?)", text_color="red")
                errors_found = True
                
            if 'reg' in res:
                self.target_reg = res['reg']
                self.lbl_reg.configure(text="Acquisito (Auto)", text_color="green")
            elif 'reg_err' in res:
                self.lbl_reg.configure(text="Errore Acquisizione", text_color="red")
                errors_found = True
                
            if errors_found:
                self.lbl_status.configure(text="Stato: Acquisizione massiva parziale (Controlla i rossi)", text_color="orange")
                messagebox.showwarning("Acquisizione Parziale", "Alcuni artefatti non sono stati acquisiti automaticamente.\nSpesso è dovuto alla mancanza dei privilegi di Amministratore (obbligatori per EVTX e VSS).\n\nI file evidenziati in verde sono comunque pronti per l'analisi.")
            else:
                self.lbl_status.configure(text="Stato: Acquisizione massiva completata con successo.", text_color="green")

        self.run_in_background("Acquisizione massiva in corso (TXT, EVTX, DAT)...", _do_fetch_all, cb)

    # --- ORCHESTRAZIONE ANALISI ---
    def run_analysis(self):
        if not any([self.target_txt, self.target_evtx, self.target_reg]):
            messagebox.showwarning("Vuoto", "Acquisisci almeno un file.")
            return

        def _do_ml_analysis():
            findings = []
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
            return findings

        def cb(findings, err):
            self.hide_loader()
            if err: 
                messagebox.showerror("Errore ML", err)
            else:
                self.lbl_status.configure(text="Stato: Analisi completata.", text_color="green")
                if findings: self.show_results(findings)
                else: messagebox.showinfo("OK", "Nessun malware trovato.")

        self.run_in_background("Elaborazione ML in corso...", _do_ml_analysis, cb)

    # --- PRESENTAZIONE TABELLA E DETTAGLI ---
    def show_results(self, findings):
        top = ctk.CTkToplevel(self)
        top.title("Analisi Completata")
        top.geometry("1100x500")
        top.attributes("-topmost", True)
        top.configure(fg_color="#121212")
        
        ctk.CTkLabel(top, text="💡 Suggerimento: Fai doppio clic su una riga per visualizzare il payload formattato.", 
                     text_color="#888888", font=("Arial", 11, "italic")).pack(pady=(10,0))
        
        style = ttk.Style(top)
        style.theme_use("default")
        
        style.configure("Treeview", background="#1e1e1e", foreground="white", fieldbackground="#1e1e1e", rowheight=30, borderwidth=0)
        style.map('Treeview', background=[('selected', '#3a3a3a')])
        
        style.configure("Treeview.Heading", background="#2b2b2b", foreground="white", relief="flat", font=("Arial", 10, "bold"))
        style.map("Treeview.Heading", background=[('active', '#3e3e3e')])

        cols = ("Data", "Livello", "Score", "Origine", "Comando")
        tree = ttk.Treeview(top, columns=cols, show='headings', style="Treeview")
        
        for c in cols: 
            tree.heading(c, text=c, command=lambda _col=c: self.sort_treeview(tree, _col, False))
            tree.column(c, width=150, anchor="center")
            
        tree.column("Comando", width=450, anchor="w")
        tree.pack(fill="both", expand=True, padx=20, pady=10)
        
        tree.tag_configure('critico', foreground='#ff4d4d')
        tree.tag_configure('sospetto', foreground='#f1c40f')

        for f in findings:
            tag = ''
            if f["level"].upper() == "CRITICO": tag = 'critico'
            elif f["level"].upper() == "SOSPETTO": tag = 'sospetto'
            
            tree.insert("", "end", values=(f["timestamp"], f["level"], f"{f['score']:.2f}%", f["source"], f["command"]), tags=(tag,))

        tree.bind("<Double-1>", self.on_row_double_click)
        self.sort_treeview(tree, "Score", True)

    def beautify_powershell(self, code_str):
        lines = [line.strip() for line in code_str.split(";") if line.strip()]
        beautified_lines = []
        indent_level = 0
        indent_space = "    " 
        
        for line in lines:
            line = line.replace(" | ", f"\n{indent_space * (indent_level + 1)}| ")
            if "{" in line:
                line = line.replace("{", "{\n" + (indent_space * (indent_level + 1)))
                indent_level += 1
            if "}" in line:
                indent_level = max(0, indent_level - 1)
                line = line.replace("}", "\n" + (indent_space * indent_level) + "}")
            beautified_lines.append((indent_space * indent_level) + line + ";")
            
        return "\n\n".join(beautified_lines)

    def on_row_double_click(self, event):
        tree = event.widget
        selected = tree.selection()
        if not selected: return
        
        item = tree.item(selected[0])
        values = item['values']
        if not values: return
        
        timestamp = values[0]
        level = values[1]
        score = values[2]
        source = values[3]
        raw_command = values[4]
        
        formatted_command = self.beautify_powershell(raw_command)
        color = "#ff4d4d" if level == "CRITICO" else "#f1c40f"
        
        viewer = ctk.CTkToplevel(self)
        viewer.title(f"Dettaglio Forense - {timestamp}")
        viewer.geometry("900x500")
        viewer.attributes("-topmost", True)
        viewer.configure(fg_color="#0a0a0a")
        
        header_text = f"Origine: {source}  |  Score: {score}  |  Rilevamento: {level}"
        ctk.CTkLabel(viewer, text=header_text, font=("Arial", 14, "bold"), text_color=color).pack(pady=(15, 5), padx=20, anchor="w")
        
        textbox = ctk.CTkTextbox(viewer, font=("Consolas", 14), text_color="#00ff00", fg_color="#1a1a1a", wrap="word")
        textbox.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        textbox.insert("0.0", formatted_command)
        textbox.configure(state="disabled")

    def sort_treeview(self, tree, col, reverse):
        items = [(tree.set(k, col), k) for k in tree.get_children('')]
        
        if col == "Score":
            items.sort(key=lambda t: float(t[0].replace('%', '')) if t[0] != "N/D" else 0.0, reverse=reverse)
        elif col == "Data":
            def parse_date(date_str):
                try:
                    clean_str = date_str.replace(" (File)", "").strip()
                    return datetime.strptime(clean_str, "%d-%m-%Y %H:%M:%S").timestamp()
                except: return 0 if not reverse else float('inf')
            items.sort(key=lambda t: parse_date(t[0]), reverse=reverse)
        else:
            items.sort(key=lambda t: t[0].lower(), reverse=reverse)
            
        for index, (val, k) in enumerate(items): tree.move(k, '', index)
        tree.heading(col, command=lambda _col=col: self.sort_treeview(tree, _col, not reverse))


if __name__ == "__main__":
    app = ForensicApp()
    app.mainloop()