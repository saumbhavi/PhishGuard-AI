import os
import base64
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def scan_url(url):

    if not API_KEY:
        return {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "error": "VIRUSTOTAL_API_KEY not set. Add it to your .env file.",
        }

    try:
        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().strip("=")

        headers = {"x-apikey": API_KEY}

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=15
        )

        if response.status_code == 404:
            return {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "error": "URL not found in VirusTotal database"
            }

        response.raise_for_status()
        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }

    except Exception as e:
        return {
            "error": str(e),
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0
        }
