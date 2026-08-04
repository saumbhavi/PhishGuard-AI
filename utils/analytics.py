import pandas as pd
import os

LOG_FILE = "logs/scan_history.csv"

def load_stats():

    if not os.path.exists(LOG_FILE):

        return {
            "total": 0,
            "safe": 0,
            "suspicious": 0,
            "malicious": 0
        }

    df = pd.read_csv(LOG_FILE)

    return {
        "total": len(df),
        "safe": len(df[df["Classification"] == "Safe"]),
        "suspicious": len(df[df["Classification"] == "Suspicious"]),
        "malicious": len(df[df["Classification"] == "Malicious"])
    }
def get_recent_scans():

    if not os.path.exists(LOG_FILE):
        return pd.DataFrame()

    df = pd.read_csv(LOG_FILE)

    return df.tail(10).iloc[::-1]