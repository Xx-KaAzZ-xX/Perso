$ubuntuPackage = "$PSScriptRoot\Ubuntu.zip"
$wslUpdate = "$PSScriptRoot\wsl_update_x64.msi"
$dssDir = "$PSScriptRoot\dataiku-dss-8.0.4.tar.gz"
$dssDependencies = "$PSScriptRoot\DSS_DPKG_DEPENDENCIES"
$bash_script="$PSScriptRoot\install-DSS.sh"
$username = whoami
$username = ($username -split '\\')[-1]

echo "This script will update WSL, install Ubuntu & Dataiku DSS..."
pause 
## Step 3 : Update de WSL en installant le msi
Start-Process msiexec.exe -Wait -ArgumentList "/I $wslUpdate"
wsl --set-default-version 2
##Step 4 : installation du package Linux/Ubuntu
Expand-Archive $PSScriptRoot\Ubuntu.zip $PSScriptRoot\Ubuntu
$ubuntuExe = "$PSScriptRoot\Ubuntu\ubuntu2004.exe"
$arguments = "install --root"
Start-Process $ubuntuExe $arguments -Wait

##Launch DSS installation script
echo $PSScriptRoot
bash -c "/mnt/c/Users/$username/Documents/Script_DSS/install-DSS.sh"
