# Disposable E07 Windows NodeRestartSeed fixture only. Never production enrollment.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Security
$r=[Console]::In.ReadToEnd() | ConvertFrom-Json
$root=[IO.Path]::GetFullPath([string]$r.root)
if(-not [IO.Path]::IsPathRooted($root) -or [IO.Directory]::Exists($root) -or [IO.File]::Exists($root)){throw 'fresh absolute disposable root required'}
[IO.Directory]::CreateDirectory($root) | Out-Null
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User
function Secure($p,[bool]$dir){
 $acl=Get-Acl -LiteralPath $p
 $acl.SetOwner($owner)
 $acl.SetAccessRuleProtection($true,$false)
 foreach($ace in @($acl.Access)){[void]$acl.RemoveAccessRuleAll($ace)}
 $inherit=if($dir){[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit}else{[Security.AccessControl.InheritanceFlags]::None}
 foreach($sid in @($owner,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))){
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
 }
 Set-Acl -LiteralPath $p -AclObject $acl
}
Secure $root $true
$seed=Join-Path $root 'node.dpapi'
$entropy=[Text.Encoding]::UTF8.GetBytes('Ptah E07 canonical NodeRestartSeed v1|' + $owner.Value)
$raw=[Text.Encoding]::UTF8.GetBytes([string]$r.seed)
$protected=[Security.Cryptography.ProtectedData]::Protect($raw,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
$stream=[IO.FileStream]::new($seed,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
try {$stream.Write($protected,0,$protected.Length);$stream.Flush($true)}finally{$stream.Dispose()}
Secure $seed $false
[Console]::Out.Write('{"status":"fixture-created"}')
