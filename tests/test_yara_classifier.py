import pytest
from inspector.yara_classifier import YARAClassifier


@pytest.fixture
def classifier():
    return YARAClassifier()


def test_python_source_code(classifier):
    body = b"import os\nimport sys\ndef main():\n    pass\nclass Foo:\n    return None"
    category, confidence = classifier.classify(body)
    assert category == "source_code"
    assert confidence >= 0.85


def test_credential_config_string(classifier):
    body = b"Some credential: password = secret123"
    category, confidence = classifier.classify(body)
    assert category == "credentials"
    assert confidence >= 0.8


def test_clean_text_returns_clean(classifier):
    body = b"hello world"
    category, confidence = classifier.classify(body)
    assert category == "clean"
    assert confidence == 0.0