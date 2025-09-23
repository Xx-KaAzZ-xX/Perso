#!/bin/bash

SRC="$1"
DST="${SRC}-repos"

# 1. Télécharger tous les dépôts
mkdir -p "$DST"
cd "$DST" || exit 1

echo "[+] Téléchargement des dépôts de $SRC ..."
#repos=$(curl -s "https://api.github.com/users/$SRC/repos?per_page=100" | jq -r '.[].clone_url')
repos=$(curl -s "https://api.github.com/orgs/$SRC/repos?per_page=100" | jq -r '.[].clone_url')


while IFS= read -r repo; do
    echo "[+] Clonage de $repo ..."
    git clone "$repo"
done <<< "$repos"

# 2. Parcourir chaque dépôt
for dir in */; do
    echo -e "\n[>] Analyse du dépôt: $dir"
    cd "$dir" || continue

    # 3. Trouver tous les commits avec des suppressions
    mapfile -t deleted_commits < <(git log --diff-filter=D --pretty=format:"%H")

    for commit in "${deleted_commits[@]}"; do
        echo "[+] Suppressions dans le commit: $commit"

        # 4. Lister les fichiers supprimés dans ce commit
        mapfile -t deleted_files < <(git show --pretty="" --name-status "$commit" | awk '$1 == "D" {print $2}')

        for file in "${deleted_files[@]}"; do
            echo "    ↳ Restauration de: $file"
            # Récupérer le fichier supprimé depuis le commit parent
            git checkout "${commit}^" -- "$file" 2>/dev/null
        done
    done

    cd ..
done

echo -e "\n✅ Tous les fichiers supprimés ont été restaurés (s'ils étaient accessibles dans l'historique)."

