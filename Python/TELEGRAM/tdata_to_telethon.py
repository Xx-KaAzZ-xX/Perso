import argparse
import shutil
import os
import sqlite3
from opentele.td import TDesktop

def extract_messages(db_path):
    """ Extrait et affiche les messages stockés en local. """
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT dialog_id, message_id, data FROM messages")
        messages = cursor.fetchall()

        print("Messages extraits :")
        for msg in messages:
            print(f"Chat ID: {msg[0]}, Message ID: {msg[1]}, Contenu: {msg[2]}")

        conn.close()
    except Exception as e:
        print(f"Erreur lors de l'extraction des messages : {e}")

def extract_contacts(db_path):
    """ Extrait et affiche la liste des contacts. """
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT first_name, last_name, phone FROM contacts")
        contacts = cursor.fetchall()

        print("\nContacts extraits :")
        for contact in contacts:
            print(f"Nom: {contact[0]} {contact[1]}, Téléphone: {contact[2]}")

        conn.close()
    except Exception as e:
        print(f"Erreur lors de l'extraction des contacts : {e}")

def copy_media(tdata_folder, output_folder):
    """ Copie les fichiers médias récupérables. """
    try:
        media_folder = os.path.join(tdata_folder, "user_data")
        if not os.path.exists(media_folder):
            print("Dossier de médias introuvable.")
            return

        os.makedirs(output_folder, exist_ok=True)

        for root, _, files in os.walk(media_folder):  # Parcours récursif des fichiers
            for file in files:
                src = os.path.join(root, file)
                dst = os.path.join(output_folder, os.path.relpath(src, media_folder))
                
                os.makedirs(os.path.dirname(dst), exist_ok=True)  # Créer les dossiers nécessaires
                shutil.copy2(src, dst)

        print(f"Médias copiés dans {output_folder}")
    except Exception as e:
        print(f"Erreur lors de la copie des médias : {e}")

def main():
    parser = argparse.ArgumentParser(description="Extraction de données Telegram Desktop depuis un dossier tdata")
    parser.add_argument("-d", "--directory", required=True, help="Chemin du dossier tdata")
    parser.add_argument("-o", "--output", default="output", help="Dossier de sortie pour les médias")
    args = parser.parse_args()

    tdata_folder = args.directory  # Correction ici

    try:
        # Chargement du dossier tdata
        tdesk = TDesktop(tdata_folder)

        if not tdesk.isLoaded():
            print("Erreur : Impossible de charger le dossier tdata.")
            return

        print(f"tdata chargé depuis : {tdata_folder}")
        print(f"Utilisateur Telegram ID : {tdesk.mainAccount.UserId}")

        # Extraction des messages si la base est disponible
        messages_db = os.path.join(tdata_folder, "D877F783D5D3EF8C")  # Base de messages
        if os.path.exists(messages_db):
            extract_messages(messages_db)
        else:
            print("Base de messages introuvable.")

        # Extraction des contacts si la base est disponible
        contacts_db = os.path.join(tdata_folder, "contacts.sqlite")  # Base de contacts
        if os.path.exists(contacts_db):
            extract_contacts(contacts_db)
        else:
            print("Base de contacts introuvable.")

        # Extraction des fichiers médias
        copy_media(tdata_folder, args.output)

    except Exception as e:
        print(f"Erreur générale : {e}")

if __name__ == "__main__":
    main()

