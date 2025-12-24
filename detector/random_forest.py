from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# 1. Prepariamo i dati (Dati inventati per l'esempio)
# Feature: [filemodCount, usa_powershell (0/1), tentativi_connessione_rete]
X = [
    [10, 1, 2],    # Software pulito
    [1500, 1, 50], # Malware (molti file modificati, molta rete)
    [5, 0, 1],     # Software pulito
    [2000, 1, 80], # Malware
    [20, 1, 0]      # Software pulito
]

# Target: 0 = Safe, 1 = Malware
y = [0, 1, 0, 1, 0]

# 2. Dividiamo i dati: una parte per imparare (Train), una per testare (Test)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# 3. Creiamo il modello (L'albero di decisione)
modello = DecisionTreeClassifier()

# 4. Allenamento: "Studia i dati"
modello.fit(X_train, y_train)

# 5. Predizione: "Fai l'esame"
previsioni = modello.predict(X_test)

print(f"Accuratezza del modello: {accuracy_score(y_test, previsioni) * 100}%")