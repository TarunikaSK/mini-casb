import os
import sys
from pathlib import Path

class DataProcessor:
    def __init__(self, path):
        self.path = path

    def process(self):
        for item in Path(self.path).iterdir():
            return item.name

def main():
    processor = DataProcessor("/tmp/data")
    result = processor.process()
    return result

if __name__ == "__main__":
    main()