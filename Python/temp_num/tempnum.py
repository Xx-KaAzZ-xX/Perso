#!/usr/bin/env python
# coding: utf-8
# By Sandaru Ashen: https://github.com/Sl-Sanda-Ru,https://t.me/Sl_Sanda_Ru

import os
import subprocess
import random
import time
import sys
import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import requests
import colorama
import pyfiglet
import pyperclip

def warn(message: str) -> None:
    print(f"\x1b[1m\x1b[31m[!] {message}".center(os.get_terminal_size().columns))


def info(message: str) -> None:
    print(f"\x1b[1m\x1b[92m[+] {message}".center(os.get_terminal_size().columns))


BLU = colorama.Style.BRIGHT + colorama.Fore.BLUE
CYA = colorama.Style.BRIGHT + colorama.Fore.CYAN
GRE = colorama.Style.BRIGHT + colorama.Fore.GREEN
YEL = colorama.Style.BRIGHT + colorama.Fore.YELLOW
RED = colorama.Style.BRIGHT + colorama.Fore.RED
MAG = colorama.Style.BRIGHT + colorama.Fore.MAGENTA
LIYEL = colorama.Style.BRIGHT + colorama.Fore.LIGHTYELLOW_EX
LIRED = colorama.Style.BRIGHT + colorama.Fore.LIGHTRED_EX
LIMAG = colorama.Style.BRIGHT + colorama.Fore.LIGHTMAGENTA_EX
LIBLU = colorama.Style.BRIGHT + colorama.Fore.LIGHTBLUE_EX
LICYA = colorama.Style.BRIGHT + colorama.Fore.LIGHTCYAN_EX
LIGRE = colorama.Style.BRIGHT + colorama.Fore.LIGHTGREEN_EX
BOLD = colorama.Style.BRIGHT
CLEAR = "cls" if os.name == "nt" else "clear"
COLORS = BLU, CYA, GRE, YEL, RED, MAG, LIYEL, LIRED, LIMAG, LIBLU, LICYA, LIGRE
FONTS = (
    "basic",
    "o8",
    "cosmic",
    "graffiti",
    "chunky",
    "epic",
    "doom",
    "avatar",
)  #'poison'
HEADERS = {"accept-encoding": "gzip", "user-agent": "okhttp/4.9.2"}
global font
font = random.choice(FONTS)
colorama.init(autoreset=True)



def fetch_authkey() -> str:
    url = "https://api-1.online/post/"
    params = {"action": "get_encrypted_api_key", "type": "user"}
    json = {"api": "111"}
    rq = requests.post(url, params=params, headers=HEADERS, json=json)
    return rq.json()["api_key"]


def decrypt_key(encrypted_str: str) -> str:
    decode = base64.b64decode(encrypted_str)  # Decode the Base64
    # Split the decoded data into IV and the actual encrypted data
    iv = decode[:16]
    encrypted_data = decode[16:]
    cipher = AES.new(
        "9e8986a75ffa32aa187b7f34394c70ea".encode(), AES.MODE_CBC, iv
    )  # AES cipher with CBC mode and the provided key and IV
    decrypted_data = unpad(
        cipher.decrypt(encrypted_data), AES.block_size
    )  # Decryption and unpad the result
    return decrypted_data.decode()


AUTH_KEY = decrypt_key(fetch_authkey())
with open('auth_key.txt', "w") as file:
    file.write(AUTH_KEY)
    file.close



def fetch_countries() -> dict:
    url = "https://api-1.online/get/"
    params = {"action": "country"}
    return requests.post(url, params=params, headers=HEADERS).json()["records"]


def fetch_numbers(country: str, page: int) -> dict:
    url = "https://api-1.online/post/"
    params = {"action": "GetFreeNumbers", "type": "user"}
    headers = HEADERS.copy()
    headers["authorization"] = "Bearer " + AUTH_KEY
    json = {"country_name": country, "limit": 10, "page": page}
    return requests.post(url, params=params, headers=headers, json=json).json()




def main():
    try:
        tmp_countries = fetch_countries()
        for iteration, i in enumerate(tmp_countries, start=1):
            print(
                f'{random.choice(COLORS)}{iteration}. {i["country_code"]} {i["Country_Name"]}'.center(
                    os.get_terminal_size().columns
                )
            )
        while True:
            try:
                choice = int(input(BOLD + "\tEnter Required Country No: "))
                if choice <= 0 or choice > len(tmp_countries):
                    warn("Wrong Input")
                else:
                    break
            except ValueError:
                warn("Wrong Input")
            except KeyboardInterrupt:
                exit(0)
        page = fetch_numbers(tmp_countries[choice - 1]["Country_Name"], 1)
        list_numbers = page["Available_numbers"]
        if page["Total_Pages"] == 0:
            warn("No numbers available")
            time.sleep(1.2)
            main()
        for i in range(2, page["Total_Pages"] + 1):
            list_numbers.extend(
                fetch_numbers(
                    tmp_countries[choice - 1]["Country_Name"],
                    i,
                )["Available_numbers"]
            )
            if len(list_numbers) > 149:
                break
        for iteration, i in enumerate(list_numbers, start=1):
            print(
                "{}{}. {} {}".format(
                    random.choice(COLORS), iteration, i["E.164"], i["time"]
                ).center(os.get_terminal_size().columns)
            )
        while True:
            try:
                choice = input(BOLD + 'Enter Required Number "R" For Random: ')
                if int(choice) <= 0 or int(choice) > len(list_numbers):
                    warn("Wrong Input")
                else:
                    break
            except ValueError:
                if choice.isalpha() and choice.upper() == "R":
                    break
                else:
                    warn("Wrong Input")
        if choice.upper() == "R":
            per = int(len(list_numbers) * 20 / 100)
            weight = [2 for i in range(per)] + [
                1 for i in range(len(list_numbers) - per)
            ]
            rnd = random.choices(list_numbers, weights=weight, k=1)[0]["E.164"]
        while True:
            try:
                print(
                    f"{random.choice(COLORS)}Selected Number: {rnd}".center(
                        os.get_terminal_size().columns
                    )
                )
                _ = copy_clipboard(rnd)
                if not _[0] == True:
                    print(RED + _[1].center(os.get_terminal_size().columns))
                else:
                    print(
                        GRE
                        + "Number Copied To The Clipboard".center(
                            os.get_terminal_size().columns
                        )
                    )
                print_sms(rnd)
            except NameError:
                print(
                    f'{random.choice(COLORS)}Selected Number: {list_numbers[int(choice)-1]["E.164"]}'.center(
                        os.get_terminal_size().columns
                    )
                )
                _ = copy_clipboard(list_numbers[int(choice) - 1]["E.164"])
                if not _[0] == True:
                    print(RED + _[1].center(os.get_terminal_size().columns))
                else:
                    print(
                        GRE
                        + "Number Copied To The Clipboard".center(
                            os.get_terminal_size().columns
                        )
                    )
    except KeyboardInterrupt:
        main()


if __name__ == "__main__":
    main()
