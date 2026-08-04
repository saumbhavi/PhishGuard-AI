import requests
from utils.url_preprocessing import extract_domain


def get_ip_info(url):

    try:

        domain = extract_domain(url)

        if not domain:
            return None

        api_url = f"http://ip-api.com/json/{domain}"

        response = requests.get(api_url, timeout=10)

        data = response.json()

        if data["status"] == "success":

            return {
                "ip": data.get("query"),
                "country": data.get("country"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org")
            }

        else:

            return None

    except:

        return None