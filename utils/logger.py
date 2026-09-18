import json
import os

def log_event(event, filename="output.jsonl"):
    """
    Ghi kết quả parse ra file định dạng JSON Lines.
    """
    with open(filename, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
