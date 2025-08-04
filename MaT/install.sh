#!/bin/bash

HAYABUSA_URL="https://github.com/Yamato-Security/hayabusa/releases/download/v3.4.0/hayabusa-3.4.0-lin-x64-gnu.zip"
ANALYZE_MFT_URL="https://github.com/rowingdude/analyzeMFT.git"
PYTHON_REGISTRY_URL="https://github.com/williballenthin/python-registry.git"


YELLOW='\033[1;33m'
GREEN='\033[1;32m'
NC='\033[0m' # No Color (reset)

set -e

echo -e "${YELLOW}[*] Installation des paquets système requis...${NC}"
sudo apt-get update
sudo apt-get install -y \
    python3 python3-pip \
    python3-dev \
    build-essential \
    libmagic1 \
    libssl-dev \
    libffi-dev \
    python3-setuptools \
    python3-distutils \
    libfuse2 \
    unzip \
    git \
    libewf-dev \
    libtsk-dev \
    libyaml-dev

echo -e "${YELLOW}[*] Installation des bibliothèques Python requises...${NC}"
pip3 install --upgrade pip

pip3 install \
    pandas \
    requests \
    pytsk3 \
    python-magic \
    tqdm \
    pyyaml \
    base58 \
    bech32 \
    bitcoinaddress \
    mnemonic \
    tabulate \
    pycryptodome \
    sha3

echo -e "${YELLOW}[*] Installation de python-registry...${NC}"
git clone https://github.com/williballenthin/python-registry.git /tmp/python-registry
cd /tmp/python-registry
python3 setup.py install
cd
rm -rf /tmp/python-registry

echo -e "${YELLOW} [*] Vérification des dépendances locales... ${NC}"
if [ ! -d "./hayabusa" ]; then
    echo -e "${YELLOW} hayabusa est manquant dans le dossier courant ${NC}" >&2
    mkdir hayabusa
    echo -e "${YELLOW}[*] Téléchargement de hayabusa...${NC}"
    cd hayabusa
    wget "${HAYABUSA_URL}" -O hayabusa.zip
    unzip hayabusa.zip >/dev/null 2>&1
    rm hayabusa.zip
    HAYABUSA_BIN=$(ls hayabusa*)
    mv $HAYABUSA_BIN hayabusa
    chmod +x ./hayabusa
    echo -e "${GREEN} [+] hayabusa a été mis en place.Pense à mettre à jour les règles SIGMA ${NC} !"
    cd ../
fi

if ! command -v analyzeMFT.py >/dev/null 2>&1; then
    echo -e "${YELLOW} [!] analyzeMFT.py n'est pas installé.${NC}" >&2
    echo -e "${YELLOW}[*] Téléchargement de analyzeMFT.py...${NC}"
    pip install analyzeMFT
    echo -e "${GREEN}[+] analyzeMFT.py a été installé avec succès !${NC}"
fi

if ! command -v regripper >/dev/null 2>&1; then
    echo -e "${YELLOW} [!] regripper n'est pas installé.${NC}" >&2

    # Détection de la distribution et version
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        distro=$ID         # "debian" ou "ubuntu"
        version_id=$VERSION_ID  # ex: "11", "22.04"
    else
        echo "Impossible de détecter le système." >&2
        exit 1
    fi

    # Construction de l'URL selon la distribution
    if [ "$distro" = "debian" ]; then
        REGRIPPER_URL="http://ftp.de.debian.org/debian/pool/main/r/regripper/regripper_3.0~git20221205.d588019+dfsg-1.1_all.deb"
    elif [ "$distro" = "ubuntu" ]; then
        REGRIPPER_URL="http://archive.ubuntu.com/ubuntu/pool/universe/r/regripper/regripper_3.0~git20221205.d588019+dfsg-1.1_all.deb"
    else
        echo "Distribution non supportée : $distro" >&2
        exit 1
    fi
        echo -e "${YELLOW}[*] Downloading regripper...${NC}"
        wget $REGRIPPER_URL -O regripper.deb
        ## installation d'une autre dépendance avant regripper
        apt install libparse-win32registry-perl
        dpkg -i regripper.deb
        echo -e "${GREEN}[+] regripper a été installé avec succès !${NC}"
fi



echo -e "${GREEN}[+] Installation terminée. ${NC}"

