## Step 1 : check des prérequis : version Windows, et si les fichiers sont bien dans le dossier
$ubuntuPackage = "$PSScriptRoot\Ubuntu.zip"
$wslUpdate = "$PSScriptRoot\wsl_update_x64.msi"
$dssDir = "$PSScriptRoot\dataiku*.tar.gz"
$dssDependencies = "$PSScriptRoot\DSS_DPKG_DEPENDENCIES"
$dssDeployment = "$PSScriptRoot\DSS-deployment.ps1"
$winVersion = Get-ComputerInfo
$winVersion = [int]$winVersion.WindowsVersion
$username = whoami
$username = ($username -split '\\')[-1]
$bootScript = "C:\Users\$username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\script.bat"



if (!(Test-Path -Path $ubuntuPackage)){
    echo "Missing Ubuntu ZIP Archive"
    echo "Script will exit."
    exit 1
}
elseif (!(Test-Path -Path $wslUpdate)){
    echo "Missing wsl_update_x64.msi"
    echo "Script will exit"
    exit 1
}
elseif (!(Test-Path -Path $dssDir)){
    echo "Missing DSS tar.gz archive for installation"
    echo "Script will exit"
    exit 1
}
elseif (!(Test-Path -Path $dssDependencies)){
    echo "Missing DSS dependencies for installation"
    echo "Script will exit"
    exit 1
}
elseif ($winVersion -lt "1909"){
    echo "This script needs an upper version of Windows 10. You have to upgrade your windows version before running this script."
    echo "Script will exit"
    exit 1
}

else{
    echo "All prerequisites are good, installation will begin"
}

## Step 2 : Lancement de l'installation de WSL
echo "Installation of WSL and Virtual Machine Platform..."
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart



echo "Creating startup script for next run after reboot..."
echo  '@ECHO OFF' > $bootScript
echo  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File ${PSScriptRoot}\DSS-deployment.ps1" >> $bootScript
echo  'PAUSE' >> $bootScript
##convert file in UTF-8 to no get execution error
$MyRawString = Get-Content -Raw $bootScript
$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
[System.IO.File]::WriteAllLines($bootScript, $MyRawString, $Utf8NoBomEncoding)
echo "Computer will reboot..."
pause 3
Restart-Computer
