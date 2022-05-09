$login = Get-Credential
$result = "liste2.txt"


Foreach($machine in Get-Content $result){
    Invoke-Command -ComputerName $machine `
   -ScriptBlock {
        $product = Get-WmiObject win32_product | where{$_.name -eq "Sotfware_Name"}
        $product.IdentifyingNumber
        Start-Process "C:\Windows\System32\msiexec.exe" `
        -ArgumentList "/x $($product.IdentifyingNumber) /quiet /noreboot" -Wait
   } -Credential $login
}
