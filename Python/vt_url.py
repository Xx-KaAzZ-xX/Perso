#!/usr/bin/python
import requests
import argparse
import json

def get_url_analysis(url, api_key):
    headers = {
        'x-apikey': api_key
    }
    params = {
        'url': url
    }
    response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, params=params)
    if response.status_code == 200:
        analysis_id = response.json()['data']['id']
        return analysis_id
    else:
        print('Error:', response.text)
        return None

def get_url_report(analysis_id, api_key):
    headers = {
        'x-apikey': api_key
    }
    response = requests.get(f'https://www.virustotal.com/api/v3/analyses/{analysis_id}', headers=headers)
    if response.status_code == 200:
        report = response.json()
        return report
    else:
        print('Error:', response.text)
        return None

def display_report(report, scan_url):
    stats = report['data']['attributes']['stats']
    print("\n--- Report for " + scan_url +"---")
    print(f"Malicious: \033[91m{stats['malicious']}\033[0m")
    print(f"Suspicious: \033[40m{stats['suspicious']}\033[0m")
    print(f"Undetected: \033[93m{stats['undetected']}\033[0m")
    print(f"Harmless: \033[92m{stats['harmless']}\033[0m")
    print(f"Timeout: {stats['timeout']}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Submit URL to VirusTotal')
    parser.add_argument('-u', '--url', type=str, required=True, help='URL to submit')
    args = parser.parse_args()
    
    # Spécifiez votre clé API ici
    api_key = ''
    scan_url = args.url
    output_file = scan_url + ".json"

    # Soumettre l'URL pour l'analyse
    analysis_id = get_url_analysis(scan_url, api_key)
    if analysis_id:
        print('URL submitted for analysis. Analysis ID:', analysis_id)

        # Attendre que l'analyse soit terminée
        print('Waiting for analysis to complete...')
        while True:
            report = get_url_report(analysis_id, api_key)
            if report and report['data']['attributes']['status'] == 'completed':
                # Vérifier s'il y a des détections
                detections = report['data']['attributes']['stats']['malicious']
                if detections > 0:
                    print('Analysis completed. Malicious detections found.')
                    #print('Report:', report)
                    display_report(report, scan_url)
                    print("Ecriture du fichier json")
                    with open(output_file, "w") as f:
                        json.dump(report, f, indent=4)
                else:
                    print('Analysis completed. No malicious detections found.')
                break
