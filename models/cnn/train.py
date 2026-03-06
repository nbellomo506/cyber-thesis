import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, Conv1D, GlobalMaxPooling1D, Dense, Dropout
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# 1. Caricamento Dati
file_input = "../datasets/dataset_base.csv" # Assumendo il tuo file da 20k
df = pd.read_csv(file_input, sep=';')
df['command'] = df['command'].astype(str)

X = df['command'].values
y = df['malicious'].values

# 2. Preprocessing (Carattere per Carattere)
max_len = 256  # Lunghezza massima del comando da analizzare
max_chars = 100 # Numero di caratteri unici da considerare (ASCII, simboli, ecc.)

tokenizer = Tokenizer(char_level=True, lower=False) # char_level=True è il segreto
tokenizer.fit_on_texts(X)

X_seq = tokenizer.texts_to_sequences(X)
X_pad = pad_sequences(X_seq, maxlen=max_len, padding='post')

# Split 80/20
X_train, X_test, y_train, y_test = train_test_split(X_pad, y, test_size=0.2, random_state=42)

# 3. Architettura della CNN
model = Sequential([
    # Trasforma i numeri in vettori densi (spazio semantico dei caratteri)
    Embedding(input_dim=len(tokenizer.word_index) + 1, output_dim=32, input_length=max_len),
    
    # Primo strato di "sensori" che cercano pattern di 5 caratteri
    Conv1D(64, kernel_size=5, activation='relu'),
    # Secondo strato che cerca pattern di 3 caratteri (più fini)
    Conv1D(128, kernel_size=3, activation='relu'),
    
    # Prende il segnale di pericolo più forte trovato in tutto il comando
    GlobalMaxPooling1D(),
    
    # Cervello decisionale
    Dense(64, activation='relu'),
    Dropout(0.5), # Evita che il modello impari a memoria (overfitting)
    Dense(1, activation='sigmoid') # Output: 0 (sicuro) o 1 (maligno)
])

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# 4. Addestramento
print("Inizio addestramento CNN...")
model.fit(X_train, y_train, epochs=10, batch_size=32, validation_split=0.1)

# 5. Valutazione
y_pred = (model.predict(X_test) > 0.5).astype("int32")
print("\n--- REPORT PERFORMANCE CNN ---")
print(classification_report(y_test, y_pred))

# 6. Salvataggio
model.save('powershell_cnn_model.h5')
import pickle
with open('tokenizer_cnn.pkl', 'wb') as f:
    pickle.dump(tokenizer, f)