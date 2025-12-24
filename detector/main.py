import random_forest

def main():
    # Load dataset
    data = random_forest.load_data('data.csv')
    
    # Preprocess data
    X_train, X_test, y_train, y_test = random_forest.preprocess_data(data)
    
    # Train model
    model = random_forest.train_model(X_train, y_train)
    
    # Evaluate model
    accuracy = random_forest.evaluate_model(model, X_test, y_test)
    
    print(f'Model Accuracy: {accuracy:.2f}%')