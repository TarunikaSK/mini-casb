from inspector.bypass_detector import BypassDetector

detector = BypassDetector()

def test_python_disguised_as_txt():
    python_code = b"import os\ndef main():\n    pass\nclass Foo:\n    x = 1"
    assert detector.detect("notes.txt", python_code) == True

def test_legitimate_txt_passes():
    normal_text = b"hello this is a normal text file nothing to see here"
    assert detector.detect("readme.txt", normal_text) == False

def test_python_file_with_correct_extension():
    python_code = b"import os\ndef main():\n    pass"
    assert detector.detect("script.py", python_code) == False