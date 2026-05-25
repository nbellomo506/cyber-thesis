# 🛡️ Fileless Malware Forensics Analyzer

![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.7.2-orange.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Questo repository contiene il codice sorgente sviluppato per il progetto di tesi in Cybersecurity. 
Il software consiste in uno strumento di analisi forense offline progettato per l'individuazione di **fileless malware** basati su PowerShell e attacchi di tipo Living-off-the-Land (LOTL). 
Il modello Random Forest integrato è stato rigorosamente ottimizzato per massimizzare il tasso di rilevamento delle minacce, mantenendo i Falsi Positivi al minimo per prevenire fenomeni di *Alert Fatigue*.

---

## 🚀 1. Installazione

Di seguito la procedura per la configurazione dell'ambiente virtuale e l'installazione delle dipendenze necessarie per il corretto funzionamento del software.

```bash
# 1. Clonazione del repository
git clone [https://github.com/nbellomo506/cyber-thesis.git](https://github.com/nbellomo506/cyber-thesis.git)
cd cyber-thesis

# 2. Creazione dell'ambiente virtuale
python -m venv venv

# 3. Attivazione dell'ambiente virtuale
# ---> Per sistemi Windows (PowerShell):
.\venv\Scripts\activate

# ---> Per sistemi Linux o macOS:
source venv/bin/activate

# 4. Installazione delle dipendenze
pip install -r requirements.txt
```

---

## 🔎 2. Analisi Forense (Esecuzione del Tool)

Questa sezione illustra l'utilizzo del modello pre-addestrato per condurre un'analisi forense su log sospetti in uno scenario di Incident Response.

**⚠️ Attenzione:** Per consentire al software la corretta estrazione e analisi degli artefatti di sistema, è strettamente necessario avviare il terminale o il prompt dei comandi con i **Privilegi di Amministratore**.

Successivamente all'attivazione dell'ambiente virtuale, è necessario navigare nella directory dedicata all'analisi ed eseguire l'applicativo principale:

```bash
cd forensic_analysis
python app.py
```
*(Lo script si occuperà automaticamente di importare le librerie richieste, inizializzare l'interfaccia di analisi e procedere alla classificazione degli artefatti di sistema).*

---

## 🧠 3. Addestramento del Modello e Feature Engineering

Questa sezione descrive la pipeline per ricostruire il dataset o procedere al re-training dell'algoritmo di Machine Learning. Tutte le operazioni seguenti devono essere eseguite all'interno della directory `models/random_forest`.

### Fase 0: Custom Feature Engineering (`feature_engine.py`) [Opzionale]
È possibile implementare nuove metriche comportamentali o Indicatori di Compromissione (IoC) personalizzati modificando il file `models/random_forest/feature_engine.py`. Una volta integrate le nuove logiche, sarà possibile procedere alla generazione dei nuovi dati.

### Fase 1: Creazione del Dataset (`build_dataset.py`)
Al fine di ricostruire il dataset di addestramento dai log grezzi (includendo le eventuali feature o esempi aggiungi), è necessario eseguire questo script. Il processo effettua il parsing dei log, calcola le metriche definite (es. Entropia di Shannon, densità Base64) e genera in output un dataset pulito in formato `.xlsx`.

```bash
cd models/random_forest
python build_dataset.py
```

### Fase 2: Addestramento del Modello (`train.py`)
A seguito della generazione del dataset, questo script provvede all'addestramento del classificatore Random Forest. Il processo include l'esecuzione di una Cross-Validation, l'estrazione della *Feature Importance* e il salvataggio del modello aggiornato in formato `.pkl`.

```bash
cd models/random_forest
python train.py
```

### Fase 3: Ottimizzazione degli Iperparametri (`grid_search.py`)
In caso di alterazione delle feature, si raccomanda di eseguire una ricalibrazione dei parametri del modello. Lo script dedicato avvia una GridSearchCV massiccia ottimizzata per la massimizzazione della metrica F2-Score. 
**Nota:** Questa operazione è altamente intensiva a livello computazionale e richiede tempistiche di esecuzione proporzionali alle capacità hardware della macchina.

```bash
cd models/random_forest
python grid_search.py
```

---

## 📊 Benchmark

Prestazioni registrate a seguito del processo di ottimizzazione tramite Grid Search:
* **Accuratezza:** 98.47%
* **Precision:** 98.71%
* **Recall:** 98.22%
* **Falsi Positivi:** ~1.2% (Solo 54 casi su oltre 4200 script benigni analizzati)

## 🏆 Riconoscimenti
Si ringrazia il **DAS Lab** per aver fornito il dataset originale utilizzato per le fasi di addestramento, validazione e collaudo del modello di Machine Learning presentato in questo progetto.
https://github.com/das-lab/mpsd

## 📝 Licenza
Il progetto è distribuito sotto licenza MIT. Sviluppato a scopo accademico e per utilizzi in ambito Incident Response e analisi forense.