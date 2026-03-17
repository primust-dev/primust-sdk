"""ML classifier — should be detected as execution."""
from sklearn.ensemble import RandomForestClassifier

def classify(features):
    model = RandomForestClassifier()
    return model.predict(features)
