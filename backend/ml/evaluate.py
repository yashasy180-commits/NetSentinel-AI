def evaluate_model(model, X_test, y_test):
    from sklearn.metrics import classification_report, confusion_matrix
    predictions = model.predict(X_test)
    return {
        "classification_report": classification_report(y_test, predictions, output_dict=True),
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist()
    }
