##Author. 
##Description. Script to create an APexOne offline update archive on NTFS Shared Folder 

$updateDirSource="C:\Program Files (x86)\Trend Micro\Apex One\PCCSRV\Download\"
$updateDirDestination="\\machinename\update\"
$archiveName="ApexOne"

##Stop the service
net stop w3svc
net stop OSCEIntegrationService
net stop ofcservice

## Copy files

if (Test-Path -Path $archiveName) {
    Remove-Item -Path $archiveName -Recurse -Force
    echo "Folder has been removed."
    New-Item -ItemType Directory -Path $archiveName 
} else {
    New-Item -ItemType Directory -Path $archiveName 
} 

Get-ChildItem "$updateDirSource\Engine" -Recurse | Copy-Item -Destination "$archiveName\Engine"
Get-ChildItem "$updateDirSource\Product" -Recurse | Copy-Item -Destination "$archiveName\Product"
Get-ChildItem "$updateDirSource\Pattern" -Recurse | Copy-Item -Destination "$archiveName\Pattern"
Get-ChildItem "$updateDirSource" -Filter *.zip | Copy-Item -Destination $archiveName
Get-ChildItem "$updateDirSource" -Filter *.sig | Copy-Item -Destination $archiveName

##Create a zip and put it on shared folder

if (Test-Path -Path "$updateDirDestination$archiveName.zip") {
    Remove-Item -Path "$updateDirDestination$archiveName.zip" -Force
    echo "Archive has been removed."
    Compress-Archive -Path $archiveName -DestinationPath "$updateDirDestination$archiveName.zip"
} else {
    Compress-Archive -Path $archiveName -DestinationPath "$updateDirDestination$archiveName.zip"
} 

## Restart the service

net start w3svc
net start ofcservice
#net start OSCEIntegrationService
