param([string[]]$Roots = @('D:\projects', 'D:\aimob'))
$ErrorActionPreference = 'Stop'
# Read-only TTG storage inventory. No deletion commands are present.
$queue = New-Object 'System.Collections.Generic.Queue[object]'
foreach ($r in $Roots) {
    if (Test-Path -LiteralPath $r -PathType Container) {
        $queue.Enqueue(@{Path=$r;Depth=0})
    }
}
$targets = New-Object 'System.Collections.Generic.List[object]'
while ($queue.Count -gt 0) {
    $item = $queue.Dequeue()
    if ($item.Depth -ge 8) { continue }
    try { $dirs = [IO.Directory]::EnumerateDirectories($item.Path) } catch { continue }
    foreach ($d in $dirs) {
        try { $info = Get-Item -LiteralPath $d -Force -ErrorAction Stop } catch { continue }
        if ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
        if ($info.Name -in @('.git','node_modules','.venv','venv','__pycache__','.gradle','.next')) { continue }
        if ($info.Name -eq 'target') {
            $measure = Get-ChildItem -LiteralPath $info.FullName -File -Recurse -Force -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum
            $targets.Add([pscustomobject]@{Path=$info.FullName;Bytes=[long]$measure.Sum})
            continue
        }
        $queue.Enqueue(@{Path=$info.FullName;Depth=($item.Depth+1)})
    }
}
$bytes = [long](($targets | Measure-Object -Property Bytes -Sum).Sum)
$drive = New-Object IO.DriveInfo('D')
$alerts = @()
if ($drive.AvailableFreeSpace -lt 40GB -or $drive.AvailableFreeSpace/$drive.TotalSize -lt 0.15) {
    $alerts += 'LOW_FREE_SPACE'
}
if ($bytes -gt 10GB) { $alerts += 'DUPLICATE_BUILD_OUTPUTS' }
$result = [ordered]@{
    Schema='ttg.storage.audit.windows.v1'
    UTC=[DateTime]::UtcNow.ToString('o')
    Host=[Environment]::MachineName
    CacheCount=$targets.Count
    CacheGiB=[Math]::Round(($bytes/1GB),2)
    FreeGiB=[Math]::Round(($drive.AvailableFreeSpace/1GB),2)
    Alerts=$alerts
    Top=@($targets | Sort-Object Bytes -Descending | Select-Object -First 20)
    Mode='READ_ONLY_NO_DELETION'
}
$folder = Join-Path $env:LOCALAPPDATA 'TTG\StorageHygiene'
New-Item -Path $folder -ItemType Directory -Force | Out-Null
$file = Join-Path $folder 'latest-audit.json'
[IO.File]::WriteAllText($file,($result | ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false)))
Write-Output ($result | ConvertTo-Json -Depth 5 -Compress)

