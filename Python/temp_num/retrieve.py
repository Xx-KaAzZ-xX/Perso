#!/usr/bin/python3
import requests
import sys
import os
import random
import json

# Lecture des arguments de ligne de commande
#if len(sys.argv) != 3:
#    print("Usage: ./script.py <number> <AUTH_KEY>")
#    sys.exit(1)

number = sys.argv[1]
AUTH_KEY = sys.argv[2]
HEADERS = {"accept-encoding": "gzip", "user-agent": "okhttp/4.9.2"}

# Fonction pour récupérer les SMS
def fetch_sms(number: str) -> list:
    url = "https://api-1.online/post/getFreeMessages"
    json_data = {"no": number, "page": "1"}
    headers = HEADERS.copy()
    headers["authorization"] = "Bearer " + AUTH_KEY
    try:
        response = requests.post(url, headers=headers, json=json_data).json()["messages"]
        return response
    except (requests.RequestException, KeyError) as e:
        print(f"Erreur lors de la récupération des messages : {e}")
        return []

# Fonction pour afficher les SMS
def print_sms(number: str) -> None:
    sms_list = fetch_sms(number)
    print(sms_list)
    if not sms_list:
        print("Aucun message trouvé.")
        return

    for i in sms_list:
        try:
            print(
                "{}{} {} {}".format(
                    i.get("FromNumber", "Inconnu"),
                    repr(i.get("Messagebody", "Message vide")),
                    i.get("message_time", "Inconnu"),
                )
            )
        except KeyError as e:
            print(f"Message mal formé : {e}")


# Exécution principale
if __name__ == "__main__":
    print_sms(number)

