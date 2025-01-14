#!/bin/bash

OUTPUT_DIR="./exported_csv"
MYSQL_USER="root"
MYSQL_PASS="" # Leave blank if no password
MYSQL_HOST="localhost"
MYSQL_TABLENAME="wp_usermeta"
# Create output directory
mkdir -p "$OUTPUT_DIR"

# Get list of all databases
DATABASES=$(mysql -u "$MYSQL_USER" -h "$MYSQL_HOST" -e "SHOW DATABASES;" | grep -v -E "(Database|information_schema|performance_schema|mysql|sys)")
#DATABASES=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -h "$MYSQL_HOST" -e "SHOW DATABASES;" | grep -v -E "(Database|information_schema|performance_schema|mysql|sys)")

for DB in $DATABASES; do
    # Check if wp_usermeta exists
    TABLE_EXISTS=$(mysql -u "$MYSQL_USER" -h "$MYSQL_HOST" -e "USE $DB; SHOW TABLES LIKE \"$MYSQL_TABLENAME\";")
    #TABLE_EXISTS=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -h "$MYSQL_HOST" -e "USE $DB; SHOW TABLES LIKE 'wp_usermeta';")
    if [[ $TABLE_EXISTS == *"$MYSQL_TABLENAME"* ]]; then
        echo "Exporting $MYSQL_TABLENAME from database $DB..."
        mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -h "$MYSQL_HOST" -e "SELECT * FROM $DB.$MYSQL_TABLENAME;" \
        | sed 's/\t/;/g' > "$OUTPUT_DIR/${DB}_$MYSQL_TABLENAME.csv"
    else
        echo "Table $MYSQL_TABLENAME not found in $DB."
    fi
done

echo "Export completed. Files are in $OUTPUT_DIR."
