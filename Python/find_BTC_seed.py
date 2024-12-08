import os
import string

# Charger le dictionnaire BIP39 en anglais sous forme de set
from mnemonic import Mnemonic
mnemo = Mnemonic("english")
bip39_words = set(mnemo.wordlist)  # Set des 2048 mots BIP39

# Fonction pour extraire les chaînes imprimables d'un fichier et les découper en mots individuels
def extract_printable_strings(file_path):
    printable_set = set()
    try:
        # Ouverture du fichier en mode binaire pour éviter les problèmes d'encodage
        with open(file_path, 'rb') as f:
            byte_data = f.read()

            # Convertir les données binaires en caractères imprimables (ASCII, sans contrôle)
            current_string = []
            for byte in byte_data:
                char = chr(byte)
                if char in string.printable and char not in string.whitespace:  # Si c'est un caractère imprimable et non un espace
                    current_string.append(char)
                else:
                    if current_string:
                        # Ajouter la chaîne trouvée (convertie en une chaîne de caractères)
                        printable_set.add(''.join(current_string))
                        current_string = []
            if current_string:
                printable_set.add(''.join(current_string))  # Ajouter la dernière chaîne si elle existe

        # Découper chaque chaîne en mots
        words_set = set()
        for printable_string in printable_set:
            words = printable_string.split()  # Découper la chaîne en mots
            words_set.update(words)  # Ajouter tous les mots dans le set

        return words_set

    except Exception as e:
        print(f"Erreur lors de l'extraction des chaînes du fichier {file_path}: {e}")
        return set()

# Fonction principale pour parcourir un répertoire et analyser les fichiers
def find_btc_seed_in_files(directory, min_matches=11):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            #print(f"Analyse du fichier : {file_path}")

            # Extraire les mots imprimables du fichier
            printable_words = extract_printable_strings(file_path)

            # Faire l'intersection entre les mots imprimables et le dictionnaire BIP39
            matches = printable_words.intersection(bip39_words)

            # Si le nombre de matchs est supérieur au seuil, on affiche le fichier
            if len(matches) >= min_matches:
                print(f"Seed potentielle trouvée dans le fichier : {file_path}")
                print(f"Nombre de mots BIP39 trouvés : {len(matches)}")
                print(f"Mots trouvés : {matches}")
                print("-" * 50)

# Exemple d'appel de la fonction (parcourir le répertoire souhaité)
find_btc_seed_in_files("/home/sansforensics/.local/", min_matches=11)

