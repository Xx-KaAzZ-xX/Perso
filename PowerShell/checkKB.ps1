#check existence of a kb

param(
[string]$kbID
)

$computerName = (Get-WmiObject -Class Win32_ComputerSystem -Property Name).Name
$kb = Get-HotFix -ComputerName $computerName | Select-String -Pattern "$kbID"

if (!$kb){
    echo "Patch not found on $computerName"
}

else{
    echo "Patch $kbID was applicated on the system."
}

exit 0