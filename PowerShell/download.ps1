#Script to download all files of a specific extension from a web page

Param(
    [string]$url=$(""),
    [string]$extension=$("")
    )
#Variables definition
$scriptDir = Split-Path $script:MyInvocation.MyCommand.Path
$cookie=""
$file="links.txt"
$file2="links2.txt"
$name="download_folder"
$path=$scriptDir + "\" + $name

function usage{

echo "Utilisation du script : ./download.ps1 -url http://mescouillesenski.com -extension .png"
exit 1

}

if (!$url -or !$extension)
{ 
usage
}

try
{
    $response = Invoke-WebRequest -URI $url
}
catch
{
    Write-Host "Une erreur est survenue avec l'url"$url
}

##On choppe tous les liens qu'on met dans un fichier links.txt
$links = $response.Links | Select href
echo $links > $file
#On ne récupère que les liens qui matchent avec l'extension voulue. Ces liens vont en links2.txt
Get-Content $file | Where-Object {$_ -match $extension} | Set-Content $file2
Remove-Item $file
New-Item -Path $path -ItemType directory
#On télécharge le tout dans le dossier
foreach($line in Get-Content $file2) {
$dl=$url+$line
$save=$path+"\"+$line
wget $dl -outfile $save
}
echo "Download finish !"
Remove-Item $file2
