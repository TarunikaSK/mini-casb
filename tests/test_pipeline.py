import pytest
from inspector.pipeline import inspect

def test_aws_key_caught_by_regex():
    body = b"AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    result = inspect("test.txt", body)
    assert result["category"] == "credentials"
    assert result["confidence"] >= 0.75
    assert result["detected_by"] == "regex"

def test_source_code_caught_by_yara():
    body = b"""
import os
import sys

class DataProcessor:
    def process(self, data):
        return data

def main():
    processor = DataProcessor()
    if __name__ == '__main__':
        main()
"""
    result = inspect("test.txt", body)
    assert result["category"] == "source_code"
    assert result["confidence"] >= 0.75
    assert result["detected_by"] == "yara"

def test_business_memo_caught_by_ollama():
    body = b"""
    Dear John Smith,
    Please find attached the Q3 report for review.
    You can reach me at john.smith@company.com or 415-555-0192.
    My address is 123 Market Street, San Francisco, CA 94105.
    Best regards, Sarah Connor
    """
    result = inspect("test.txt", body)
    assert result["category"] in ("pii", "ip")
    assert result["detected_by"] == "ollama"

def test_clean_text_returns_clean():
    body = b"hello world this is a normal sentence"
    result = inspect("test.txt", body)
    assert result["category"] == "clean"