import customtkinter as ctk
from tkinter import filedialog, messagebox
from tkinter import ttk 
import pandas as pd
import sys
import os
import shutil
import subprocess
import ctypes
from Registry import Registry


# 1. Trova il percorso della cartella 'progetto'
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(parent_dir)

try:
    from models.random_forest.predict import extract_features_dict, load_model
    print("Moduli caricati con successo!")
except ImportError as e:
    from .models.random_forest.predict import extract_features_dict, load_model
    print(f"Errore: {e}")

class ForensicApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PowerShell Forensic Analyzer - ML Edition")
        self.geometry("700x550")
        
        # --- CARICAMENTO DEL MODELLO AI ---
        self.model = None
        try:
            # Assicurati che il nome del file corrisponda a quello che hai salvato prima
            # Se il file è nella stessa cartella dello script, basta il nome:
            model_path = "../models/random_forest/modello_powershell_classifier.pkl"
            
            # Oppure, se è nella cartella genitore:
            # model_path = os.path.join(parent_dir, "best_rf_model_f2.pkl")
            
            self.model = load_model(model_path)
            print("[OK] Modello AI caricato e pronto per l'inferenza.")
        except Exception as e:
            print(f"[!] Errore critico nel caricamento del modello: {e}")
            # Mostreremo un avviso se il file .pkl non viene trovato
            
        # Variabili per memorizzare i percorsi dei file pronti per l'analisi
        self.target_log_file = None
        self.target_reg_file = None

        self.label = ctk.CTkLabel(self, text="Acquisizione Artefatti Post-Mortem", font=("Arial", 18, "bold"))
        self.label.pack(pady=20)

        # --- FRAME LOG POWERSHELL ---
        self.frame_log = ctk.CTkFrame(self)
        self.frame_log.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(self.frame_log, text="1. Cronologia / Log PowerShell:", font=("Arial", 14, "bold")).pack(pady=5)
        self.lbl_log_status = ctk.CTkLabel(self.frame_log, text="Nessun file caricato", text_color="gray")
        self.lbl_log_status.pack()
        
        self.btn_log_man = ctk.CTkButton(self.frame_log, text="Scegli File Manualmente", command=self.load_log)
        self.btn_log_man.pack(side="left", padx=20, pady=10, expand=True)
        
        self.btn_log_auto = ctk.CTkButton(self.frame_log, text="Preleva dal Sistema (Auto)", fg_color="orange", hover_color="#cc6600", command=self.auto_fetch_history)
        self.btn_log_auto.pack(side="right", padx=20, pady=10, expand=True)

        # --- FRAME REGISTRO NTUSER.DAT ---
        self.frame_reg = ctk.CTkFrame(self)
        self.frame_reg.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(self.frame_reg, text="2. Registro di Sistema (NTUSER.DAT):", font=("Arial", 14, "bold")).pack(pady=5)
        self.lbl_reg_status = ctk.CTkLabel(self.frame_reg, text="Nessun file caricato", text_color="gray")
        self.lbl_reg_status.pack()

        self.btn_reg_man = ctk.CTkButton(self.frame_reg, text="Scegli File Manualmente", command=self.load_registry)
        self.btn_reg_man.pack(side="left", padx=20, pady=10, expand=True)
        
        self.btn_reg_auto = ctk.CTkButton(self.frame_reg, text="Preleva dal Sistema (Auto)", fg_color="orange", hover_color="#cc6600", command=self.auto_fetch_registry)
        self.btn_reg_auto.pack(side="right", padx=20, pady=10, expand=True)

        # --- BOTTONE AVVIO ---
        self.btn_run = ctk.CTkButton(self, text="AVVIA ANALISI FORENSE CON RANDOM FOREST", fg_color="red", hover_color="darkred", height=40, command=self.run_analysis)
        self.btn_run.pack(pady=30)

        self.status_label = ctk.CTkLabel(self, text="Stato: In attesa di acquisizione artefatti...")
        self.status_label.pack()

    # --- FUNZIONI CARICAMENTO MANUALE ---
    def load_log(self):
        file = filedialog.askopenfilename(title="Seleziona Log PowerShell", filetypes=[("Text/EVTX Files", "*.txt *.evtx"), ("All Files", "*.*")])
        if file:
            self.target_log_file = file
            self.lbl_log_status.configure(text=f"Pronto: {os.path.basename(file)}", text_color="green")

    def load_registry(self):
        file = filedialog.askopenfilename(title="Seleziona NTUSER.DAT", filetypes=[("DAT Files", "*.dat"), ("All Files", "*.*")])
        if file:
            self.target_reg_file = file
            self.lbl_reg_status.configure(text=f"Pronto: {os.path.basename(file)}", text_color="green")

    # --- FUNZIONI PRELIEVO AUTOMATICO ---
    def auto_fetch_history(self):
        """Preleva automaticamente il file ConsoleHost_history.txt dell'utente corrente"""
        user_profile = os.environ.get('USERPROFILE')
        history_path = os.path.join(user_profile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine', 'ConsoleHost_history.txt')
        
        if os.path.exists(history_path):
            # Copiamo il file in una directory temporanea sicura per non alterare l'originale
            temp_copy = os.path.join(os.getcwd(), 'temp_history.txt')
            try:
                shutil.copy2(history_path, temp_copy)
                self.target_log_file = temp_copy
                self.lbl_log_status.configure(text="Prelevato in automatico dal sistema!", text_color="green")
            except Exception as e:
                messagebox.showerror("Errore", f"Impossibile copiare la cronologia: {e}")
        else:
            messagebox.showwarning("Non Trovato", "Il file di cronologia PowerShell non è presente su questo sistema.")

    def is_admin(self):
        """Verifica se lo script è in esecuzione con privilegi di Amministratore"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def auto_fetch_registry(self):
        """Tenta di prelevare NTUSER.DAT, usando VSS se il file è bloccato."""
        user_profile = os.environ.get('USERPROFILE')
        ntuser_path = os.path.join(user_profile, 'NTUSER.DAT')
        temp_copy = os.path.join(os.getcwd(), 'temp_NTUSER.DAT')
        
        if not os.path.exists(ntuser_path):
            messagebox.showwarning("Non Trovato", "NTUSER.DAT non trovato sul sistema.")
            return

        try:
            # 1. Tentativo standard (funziona solo se l'utente non è loggato, raro in live forensics)
            shutil.copy2(ntuser_path, temp_copy)
            self.target_reg_file = temp_copy
            self.lbl_reg_status.configure(text="NTUSER.DAT acquisito (Standard)!", text_color="green")
            
        except PermissionError:
            # 2. Il file è bloccato. Verifichiamo i privilegi per usare VSS.
            if not self.is_admin():
                messagebox.showerror(
                    "Privilegi Insufficienti", 
                    "NTUSER.DAT è bloccato dal sistema.\n\nPer usare la Volume Shadow Copy (VSS) e forzare l'estrazione, devi avviare questo tool come Amministratore."
                )
                return
            
            # 3. Esecuzione tramite VSS
            self.status_label.configure(text="Stato: Creazione Shadow Copy in corso...")
            self.update()
            
            if self.extract_via_vss(user_profile, temp_copy):
                self.target_reg_file = temp_copy
                self.lbl_reg_status.configure(text="NTUSER.DAT acquisito (VSS)!", text_color="green")
            else:
                messagebox.showerror("Errore VSS", "Acquisizione tramite Shadow Copy fallita. Controlla i log della console.")
                
        except Exception as e:
            messagebox.showerror("Errore", f"Errore imprevisto durante l'acquisizione: {e}")
        finally:
             self.status_label.configure(text="Stato: In attesa di acquisizione artefatti...")

    def extract_via_vss(self, user_profile, dest_path):
        """Crea una Shadow Copy, copia il file e pulisce il sistema."""
        try:
            drive_letter = os.path.splitdrive(user_profile)[0]
            user_dir = os.path.basename(user_profile)
            
            # Usiamo le doppie graffe {{ }} dove PowerShell le richiede (Where-Object)
            # Usiamo le graffe singole { } dove vogliamo iniettare variabili Python
            ps_script = f"""
            $drive = '{drive_letter}\\'
            $s1 = (Get-WmiObject -List Win32_ShadowCopy).Create($drive, "ClientAccessible")
            if ($s1.ReturnValue -ne 0) {{ throw "Errore creazione VSS: $($s1.ReturnValue)" }}
            
            $s2 = Get-WmiObject Win32_ShadowCopy | Where-Object {{ $_.ID -eq $s1.ShadowID }}
            $device = $s2.DeviceObject
            
            $link = "C:\\vss_link"
            if (Test-Path $link) {{ cmd.exe /c rmdir $link }}
            
            cmd.exe /c mklink /d $link "$device\\"
            
            $src = "$link\\Users\\{user_dir}\\NTUSER.DAT"
            Copy-Item -Path "$src" -Destination "{dest_path}" -Force
            
            cmd.exe /c rmdir $link
            $s2.Delete()
            """
            
            process = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if os.path.exists(dest_path) and os.path.getsize(dest_path) > 0:
                return True
            else:
                print(f"[!] Errore PS:\n{process.stderr}")
                return False
                
        except Exception as e:
            print(f"[!] Errore Python: {e}")
            return False

    def run_analysis(self):
        if not self.target_log_file and not self.target_reg_file:
            messagebox.showwarning("Attenzione", "Devi acquisire almeno un file prima di avviare l'analisi.")
            return

        self.status_label.configure(text="Stato: Estrazione feature ed inferenza in corso...")
        self.update() 
        
        malicious_findings = []

        # --- 1. ANALISI DEI LOG POWERSHELL ---
        if self.target_log_file:
            try:
                # Leggiamo i comandi dal file di testo
                with open(self.target_log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    commands = f.readlines()
                
                # Puliamo i comandi da righe vuote
                commands = [cmd.strip() for cmd in commands if cmd.strip()]
                
                for cmd in commands:
                    # Estraiamo le feature (il dizionario)
                    features_dict = extract_features_dict(cmd)
                    
                    # Convertiamo in DataFrame per Scikit-Learn
                    # Nota: assicurati che le colonne corrispondano ESATTAMENTE a quelle del training
                    df_features = pd.DataFrame([features_dict]).fillna(0)
                    
                    # Calcoliamo la probabilità (usiamo predict_proba per avere la percentuale)
                    # [0][1] prende la probabilità della classe 1 (Malicious)
                    prob_malicious = self.model.predict_proba(df_features)[0][1]
                    
                    # Filtriamo solo ciò che è minimamente sospetto (es. > 30%)
                    if prob_malicious >= 0.30:
                        malicious_findings.append({
                            "Comando": cmd,
                            "Score": prob_malicious * 100,
                            "Livello": "CRITICO" if prob_malicious >= 0.60 else "SOSPETTO",
                            "Origine": "Console_History"
                        })
            except Exception as e:
                messagebox.showerror("Errore Log", f"Impossibile analizzare i log: {e}")

        # --- 2. ANALISI DEL REGISTRO (NTUSER.DAT) ---
        if self.target_reg_file:
            print(f"Analisi in corso su: {self.target_reg_file}")
            
            try:
                reg = Registry.Registry(self.target_reg_file)
                # Percorsi delle chiavi più "calde" per malware PowerShell
                paths_to_check = [
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                    r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
                    r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
                ]

                entries_found = []

                for path in paths_to_check:
                    try:
                        key = reg.open(path)
                        for value in key.values():
                            # Estraiamo il contenuto della chiave (spesso è il comando PS)
                            cmd_raw = str(value.value())
                            
                            # Filtro rapido: ci interessa solo se c'è p-o-w-e-r-s-h-e-l-l
                            if "powershell" in cmd_raw.lower() or "-enc" in cmd_raw.lower():
                                entries_found.append((path, value.name(), cmd_raw))
                    except Exception:
                        continue # Se la chiave non esiste, passiamo oltre

                # Ora mandiamo tutto al modello
                if entries_found:
                    for path, name, cmd in entries_found:
                        features = extract_features_dict(cmd)
                        df_input = pd.DataFrame([features]).fillna(0)
                        
                        # Usiamo il tuo modello da 54 alberi
                        prob = self.model.predict_proba(df_input)[0][1]
                        score = round(prob * 100, 2)
                        
                        # Qui popoli la tua tabella o stampi i risultati
                        print(f"[{score}%] TROVATO IN {path}: {cmd[:50]}...")
                        # self.add_to_results_table(path, name, score, cmd)
                else:
                    print("Nessuna traccia sospetta trovata nel registro.")

            except Exception as e:
                print(f"Errore durante l'analisi del registro: {e}")

        self.status_label.configure(text="Stato: Analisi completata! Modello F2 applicato.")
        
        # --- 3. MOSTRA RISULTATI ---
        if malicious_findings:
            # Ordina i risultati dal più pericoloso al meno pericoloso
            malicious_findings = sorted(malicious_findings, key=lambda x: x["Score"], reverse=True)
            self.show_results(malicious_findings)
        else:
            messagebox.showinfo("Risultato", "Analisi completata. Nessun comportamento sospetto rilevato!")

    def show_results(self, findings):
        """Crea una finestra popup per mostrare i risultati in formato tabellare."""
        result_window = ctk.CTkToplevel(self)
        result_window.title("Report Analisi Forense")
        result_window.geometry("900x500")
        
        # Stile della tabella compatibile con il tema scuro
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", rowheight=30)
        style.configure("Treeview.Heading", background="#1f538d", foreground="white", font=('Arial', 11, 'bold'))
        style.map('Treeview', background=[('selected', '#1f538d')])

        # Creazione Tabella (Treeview)
        columns = ("Livello", "Score (%)", "Origine", "Comando")
        tree = ttk.Treeview(result_window, columns=columns, show='headings')
        
        tree.heading("Livello", text="Livello")
        tree.column("Livello", width=100, anchor="center")
        
        tree.heading("Score (%)", text="Score (%)")
        tree.column("Score (%)", width=100, anchor="center")
        
        tree.heading("Origine", text="Origine")
        tree.column("Origine", width=150, anchor="center")
        
        tree.heading("Comando", text="Payload/Comando")
        tree.column("Comando", width=500, anchor="w")
        
        tree.pack(fill="both", expand=True, padx=20, pady=20)

        # Popolamento Tabella
        for item in findings:
            # Taglia i comandi troppo lunghi per non spaccare la UI
            display_cmd = item["Comando"] if len(item["Comando"]) < 150 else item["Comando"][:147] + "..."
            
            # Inserisce la riga
            tree.insert("", "end", values=(item["Livello"], f"{item['Score']:.2f}%", item["Origine"], display_cmd))
if __name__ == "__main__":
    app = ForensicApp()
    app.mainloop()