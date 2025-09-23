#!/bin/bash

# Usage: ./script.sh -d <directory> -f <output_file.csv>

# Variables par défaut
directory=""
output_file=""

# Parse des arguments
while getopts "d:f:" opt; do
  case $opt in
    d) directory="$OPTARG" ;;
    f) output_file="$OPTARG" ;;
    *) echo "Usage: $0 -d <directory> -f <output_file.csv>" ; exit 1 ;;
  esac
done

if [[ -z "$directory" || -z "$output_file" ]]; then
  echo "Usage: $0 -d <directory> -f <output_file.csv>"
  exit 1
fi

# Initialisation du fichier CSV
echo "Site,Commit_Hash,Author_Name,Author_Email,Committer_Name,Committer_Email,Commit_Message", "Commit_Date" > "$output_file"

# Recherche des dossiers contenant un .git
mapfile -t repos < <(find "$directory" -type d -name ".git" -prune | sed 's|/.git$||')

# Parcours de chaque dépôt trouvé
for repo in "${repos[@]}"; do
    site_name=$(basename "$repo")
    (
      cd "$repo" || exit
      git log --pretty=format:"$site_name,%h,%an,%ae,%cn,%ce,%s, %cd" --date=iso
    )
done >> "$output_file"

echo "Fichier CSV généré : $output_file"

