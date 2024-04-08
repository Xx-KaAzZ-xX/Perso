#!/usr/bin/python
import requests
import argparse
import json

def get_ip_analysis(ip_address, api_key):
    headers = {
        'x-apikey': api_key
    }
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        analysis = response.json()
        return analysis
    else:
        print('Error:', response.text)
        return None

def display_ip_analysis(analysis, ip_address):
    data = analysis.get('data')
    if data:
        attributes = data.get('attributes')
        if attributes:
            country = attributes.get('country', 'Unknown')
            last_analysis_results = attributes.get('last_analysis_results', {})
            malicious_found = False
            suspicious_found = False
            full_report = {}

            for engine, result in last_analysis_results.items():
                full_report[engine] = result
                if result['result'] in ['malicious', 'suspicious']:
                    malicious_found = True
                    if result['result'] == 'suspicious':
                        suspicious_found = True

            if malicious_found:
                print("\n--- Analysis Report for IP Address", ip_address, "---")
                print("Country:", country)
                print("Last Analysis Results:")
                for engine, result in full_report.items():
                    print(f"{engine}: {result.get('result', 'Unknown')}")

                output_file = ip_address + ".json"
                print("Ecriture du fichier json")
                with open(output_file, "w") as f:
                    json.dump(full_report, f, indent=4)
            elif suspicious_found:
                print("No malicious found but suspicious activities detected for the IP address.")
            else:
                print("No malicious or suspicious activity found for the IP address.")
        else:
            print("No information available for the IP address.")
    else:
        print("No data available for the IP address : " + ip_address)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Submit IP Address to VirusTotal')
    parser.add_argument('-i', '--ip_address', type=str, required=True, help='IP address to submit')
    args = parser.parse_args()

    # Spécifiez votre clé API ici
    api_key = ''
    ip_address = args.ip_address

    # Soumettre l'adresse IP pour l'analyse
    analysis = get_ip_analysis(ip_address, api_key)
    if analysis:
        print('IP Address submitted for analysis.')
        display_ip_analysis(analysis, ip_address)
