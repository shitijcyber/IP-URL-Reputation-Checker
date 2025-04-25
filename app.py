import requests
import os
from flask import Flask, jsonify, request
import base64
from flask_cors import CORS
import ipaddress

app = Flask(__name__)
CORS(app)

API_KEY = '5b5037342f458f4e86df8bbd68033787b68a133844c01ab7b89fd6ea8a92daf9'
HEADERS = {'x-apikey': API_KEY}

@app.route('/check', methods=['GET'])
def index():
    return render_template('index.html')
def check():
    try:
        query = request.args.get('query')
        print(f"Received query: {query}")

        if not query:
            return jsonify({"error": "No query parameter provided"}), 400

        # Detect if input is IP address
        is_ip = False
        try:
            ipaddress.ip_address(query)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
        else:
            formatted_url = query if query.startswith("http") else "http://" + query
            url_id = base64.urlsafe_b64encode(formatted_url.encode()).decode().strip("=")
            vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        res = requests.get(vt_url, headers=HEADERS, verify=False)
        print(f"VirusTotal response status: {res.status_code}")
        if res.status_code != 200:
            print(f"Error response from VirusTotal: {res.text}")
            return jsonify({"error": "VirusTotal API Error"}), res.status_code

        data = res.json()
        attributes = data["data"]["attributes"]
        stats = attributes["last_analysis_stats"]
        verdict = "malicious" if stats["malicious"] > 0 else "suspicious" if stats["suspicious"] > 0 else "clean"

        country = attributes.get("country", "Unknown")
        as_owner = attributes.get("as_owner", "Unknown")
        domain = attributes.get("domain", "Unknown")
        network = attributes.get("network", "Unknown")

        # Count vendors that flagged as malicious
        vendor_stats = attributes["last_analysis_results"]
        malicious_vendors = sum(1 for v in vendor_stats.values() if v["category"] == "malicious")
        total_vendors = len(vendor_stats)

        return jsonify({
            "verdict": verdict,
            "stats": stats,
            "country": country,
            "organization": as_owner,
            "domain": domain,
            "network": network,
            "malicious_vendors": malicious_vendors,
            "total_vendors": total_vendors
        })

    except requests.exceptions.RequestException as e:
        print(f"Request error: {str(e)}")
        return jsonify({"error": "Error while contacting VirusTotal"}), 500
    except KeyError as e:
        print(f"KeyError: Missing expected data from the response: {str(e)}")
        return jsonify({"error": "Error processing the response from VirusTotal"}), 500
    except Exception as e:
        print(f"General error: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
