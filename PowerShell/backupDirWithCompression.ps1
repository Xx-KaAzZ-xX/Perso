$file = "F:\file.txt"
$date = Get-Date -Format yyyyMMdd
$backupDir = "F:\$date-Backup"
$zipDir = "$backupDir.zip"
$zip = 'C:\Program Files\7-Zip\7z.exe'
$finalDestination = "F:\Backup"
$logFile = "F:\$date-Backup.log"

function Write-Log 
{ 
    [CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory=$true, 
                   ValueFromPipelineByPropertyName=$true)] 
        [ValidateNotNullOrEmpty()] 
        [Alias("LogContent")] 
        [string]$Message, 
 
        [Parameter(Mandatory=$false)] 
        [Alias('LogPath')] 
        [string]$Path="$logFile", 
         
        [Parameter(Mandatory=$false)] 
        [ValidateSet("Error","Warn","Info")] 
        [string]$Level="Info", 
         
        [Parameter(Mandatory=$false)] 
        [switch]$NoClobber 
    ) 
 
    Begin 
    { 
        # Set VerbosePreference to Continue so that verbose messages are displayed. 
        $VerbosePreference = 'Continue' 
    } 
    Process 
    { 
         
        # If the file already exists and NoClobber was specified, do not write to the log. 
        if ((Test-Path $Path) -AND $NoClobber) { 
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name." 
            Return 
            } 
 
        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path. 
        elseif (!(Test-Path $Path)) { 
            Write-Verbose "Creating $Path." 
            $NewLogFile = New-Item $Path -Force -ItemType File 
            } 
 
        else { 
            # Nothing to see here yet. 
            } 
 
        # Format Date for our Log File 
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
 
        # Write message to error, warning, or verbose pipeline and specify $LevelText 
        switch ($Level) { 
            'Error' { 
                Write-Error $Message 
                $LevelText = 'ERROR:' 
                } 
            'Warn' { 
                Write-Warning $Message 
                $LevelText = 'WARNING:' 
                } 
            'Info' { 
                Write-Verbose $Message 
                $LevelText = 'INFO:' 
                } 
            } 
         
        # Write log entry to $Path 
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append 
    } 
    End 
    { 
    } 
}

if (!(Test-Path $zip -PathType Leaf)){
    echo "$zip doesn't seem installed."
    }


if (!(Test-Path $file -PathType Leaf)){
    echo "$file doesn't exist."
    }

else{
    New-Item -Path "$backupDir" -ItemType Directory
    $content = Get-Content $file
    foreach ($line in $content){
        $files = Get-ChildItem -Path $line -Recurse -Include *.txt
        Copy-Item -Path $files -Destination $backupDir
            if($?)
        {
           Write-Log -Message "Contenu de $line copié dans $backupDir"
  
        }
        else
        {
           Write-Log -Message "Contenu de $line non copié dans $backupDir"
        }
    }
    & $zip a $zipDir $backupDir
    if($?)
    {
       Write-Log -Message "Dossier $backupDir compressé"
  
    }
    else
    {
       Write-Log -Message "Erreur lors de la compression de $backupDir"
    }
    Move-Item -Path $zipDir -Destination $finalDestination
    Remove-Item -Path $backupDir -Recurse -Force

}

