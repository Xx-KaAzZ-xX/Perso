#!/bin/bash


#.  Description : Script qui lance une indexation de documents si des fichiers (pdf, docx et ppt) sont trouvés dans le répertoire
#.  Author : Aurélien DUBUS
#.  Version : 1.0


INDEXATION_FOLDER="/mnt/DOCUMENTS_A_INDEXER"
INDEXATION_SCRIPT="/root/indexDocuments_shared_folder.py"
tmp_file="/root/file.txt"

while true; do
    file_name=$(find ${INDEXATION_FOLDER} | awk -F '/' '{print $4}' | grep '.pdf\|.docx\|.ppt' > $tmp_file)
    nb_file=$(cat ${tmp_file} | wc -l)
    if [ ${nb_file} -gt 0 ]
    then
      python ${INDEXATION_SCRIPT}
      rm ${tmp_file}
    else
    :
    fi
    sleep 5
done

exit 0
