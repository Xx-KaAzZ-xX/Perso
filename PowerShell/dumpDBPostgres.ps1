$databases = ("test1", "test2", "test3")
$user = "postgres"
$bkp_dir = "O:\DB\"
$date = Get-Date -Format yyyyMMdd

foreach ($db in $databases){
    $filename = "$bkp_dir$date$db.sql"
    C:\PostgreSQL\pg96\bin\pg_dump.exe -U $user -f "$filename" $db
}
