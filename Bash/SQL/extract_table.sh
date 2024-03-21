#!/bin/bash
#SPLIT DUMP FILE INTO INDIVIDUAL TABLE DUMPS
# Text color variables
txtund=$(tput sgr 0 1)    # Underline
txtbld=$(tput bold)       # Bold
txtred=$(tput setaf 1)    # Red
txtgrn=$(tput setaf 2)    # Green
txtylw=$(tput setaf 3)    # Yellow
txtblu=$(tput setaf 4)    # Blue
txtpur=$(tput setaf 5)    # Purple
txtcyn=$(tput setaf 6)    # Cyan
txtwht=$(tput setaf 7)    # White
txtrst=$(tput sgr0)       # Text reset

TARGET_DIR="."
DUMP_FILE=$1
TABLE_COUNT=0

usage() {
        echo "${txtbld}${txtred}Usage: ./extract_table.sh DUMP-FILE-NAME${txtrst} -- Extract all tables as a separate file from dump."
        echo "${txtbld}${txtred}       ./extract_table.sh DUMP-FILE-NAME TABLE-NAME OUTFILE-NAME.csv${txtrst} -- Extract single table from dump."
        echo "${txtbld}${txtred}       ./extract_table.sh DUMP-FILE-NAME -S TABLE-NAME-REGEXP ${txtrst} -- Extract tables from dump for specified regular expression."
      }
if [ $# = 0 ]; then
  usage
  exit
elif [ $# = 1 ]; then
        #Loop for each tablename found in provided dumpfile
        for tablename in $(grep "Table structure for table " $1 | awk -F"\`" {'print $2'})
        do
                #Extract table specific dump to tablename.sql
                sed -n "/^-- Table structure for table \`$tablename\`/,/^-- Table structure for table/p" $1 > $TARGET_DIR/$tablename.sql
                TABLE_COUNT=$((TABLE_COUNT+1))
        done;
elif [ $# = 2  ]; then
        for tablename in $(grep -E "Table structure for table \`$2\`" $1| awk -F"\`" {'print $2'})
        do
                echo "Extracting $tablename..."
                #Extract table specific dump to tablename.sql
                sed -n "/^-- Table structure for table \`$tablename\`/,/^-- Table structure for table/p" $1 > $TARGET_DIR/$tablename.sql
                TABLE_COUNT=$((TABLE_COUNT+1))
        done;
        echo "${txtbld}$TABLE_COUNT Table extracted from $DUMP_FILE at $TARGET_DIR${txtrst}"
elif [ $# = 3  ]; then
        for tablename in $(grep -E "Table structure for table \`$2\`" $1| awk -F"\`" {'print $2'})
        do
                echo "Extracting $tablename..."
                #Extract table specific dump to tablename.sql
                sed -n "/^-- Table structure for table \`$tablename\`/,/^-- Table structure for table/p" $1 > $TARGET_DIR/$tablename.sql
                TABLE_COUNT=$((TABLE_COUNT+1))
        done;
        echo "${txtbld}$TABLE_COUNT Table extracted from $DUMP_FILE at $TARGET_DIR${txtrst}"
        echo "Converting $tablename.sql into CSV File..."

        #Summary
        # Extract CSV
        outfile=${3}
        # Get the Columns
        begin_1=$(grep -n "CREATE TABLE" ${tablename}.sql | awk -F ":" '{print $1}')
        begin_2=$(echo "${begin_1} + 1" | bc)
        end_1=$(grep -n "ENGINE" ${tablename}.sql | awk -F ":" '{print $1}')
        end_2=$(echo "${end_1} - 1" | bc)
        columns_unformated=$(sed -n "${begin_2},${end_2}p" ${tablename}.sql)
        columns=()
        while IFS= read -r line; do
          column=$(echo "${line}" | awk '{print $1}' | sed 's/`/"/g')
          columns+=("${column}")
        done <<< ${columns_unformated}
        echo "${columns[*]}" > ${outfile}

        #Get the values
        begin_3=$(grep -n "INSERT INTO" ${tablename}.sql | awk -F ":" '{print $1}' | head -1)
        begin_4=$(echo "${begin_3} + 1" | bc)
        values_unformated=$(sed -n "${begin_4},\$p" ${tablename}.sql)
        #echo "${values_unformated}"
        while IFS= read -r line_values; do
          #ignore all INSERT INTO
          if [[ ${line_values} == *"INSERT INTO"* ]]; then
            continue
          fi
          value=$(echo "${line_values}" | grep -oP '\(\K[^\)]+')
          echo "${value}" >> "${outfile}"
        done <<< ${values_unformated}
        echo "Finished ! Removing ${tablename}.sql file"
        rm ${tablename}.sql
else
        usage
fi

exit 0
