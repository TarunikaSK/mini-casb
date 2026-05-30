import pytest
from inspector.ollama_classifier import OllamaClassifier


@pytest.fixture
def classifier():
    return OllamaClassifier()


def test_password_classified_as_credentials(classifier):
    body = b"Some credential: password = supersecret123"
    category, confidence = classifier.classify(body)
    assert category == "credentials"
    assert confidence > 0.6

def test_clean_text_returns_clean(classifier):
    body = b"hello world this is a normal sentence"
    category, confidence = classifier.classify(body)
    assert category == "clean"
    assert confidence > 0.0