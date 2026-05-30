import pytest
from inspector.regex_classifier import RegexClassifier


@pytest.fixture
def classifier():
    return RegexClassifier()


def test_aws_key_classified_as_credentials(classifier):
    body = b"Some config file\nAKIAIOSFODNN7EXAMPLE\nother content"
    category, confidence = classifier.classify(body)
    assert category == "credentials"
    assert confidence >= 0.9


def test_email_classified_as_pii(classifier):
    body = b"Please contact john.doe@example.com for more info"
    category, confidence = classifier.classify(body)
    assert category == "pii"
    assert confidence > 0.0


def test_clean_text_returns_clean(classifier):
    body = b"hello world"
    category, confidence = classifier.classify(body)
    assert category == "clean"
    assert confidence == 0.0