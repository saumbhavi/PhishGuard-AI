import csv
import os
from datetime import datetime

LOG_FILE = "logs/scan_history.csv"

def save_scan(user_input, score, classification):

    file_exists = os.path.isfile(LOG_FILE)

    with open(LOG_FILE, "a", newline="", encoding="utf-8") as file:

        writer = csv.writer(file)

        if not file_exists:
            writer.writerow(
                ["Timestamp", "Input", "ThreatScore", "Classification"]
            )

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            user_input,
            score,
            classification
        ])