# E07 controlled Windows DPAPI Node-state helper; launched only by the embedded E01 client.
# Input: one JSON request on stdin. No keys or Node seeds accepted on the command line.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Security
function Deny([string]$why){ throw $why }
function CheckPath([string]$path) {
 if (-not [IO.Path]::IsPathRooted($path)) { Deny 'absolute state path required' }
 $full = [IO.Path]::GetFullPath($path)
 $current = $full
 while (-not [string]::IsNullOrEmpty($current)) {
  if ([IO.File]::Exists($current) -or [IO.Directory]::Exists($current)) {
   $flags = [IO.File]::GetAttributes($current)
   if (($flags -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Deny 'reparse path rejected' }
  }
  $parent = [IO.Path]::GetDirectoryName($current)
  if ([string]::IsNullOrEmpty($parent) -or $parent -eq $current) { break }
  $current = $parent
 }
 return $full
}
function CheckAcl([string]$path) {
 $path = CheckPath $path
 if (-not [IO.File]::Exists($path) -and -not [IO.Directory]::Exists($path)) { Deny 'protected file absent' }
 $entry=if([IO.Directory]::Exists($path)){[IO.DirectoryInfo]::new($path)}else{[IO.FileInfo]::new($path)}
 $acl=$entry.GetAccessControl()
 $self=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $allowed=@($self,'S-1-5-18','S-1-5-32-544')
 if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $self){Deny 'incorrect owner'}
 if (-not $acl.AreAccessRulesProtected){Deny 'inherited ACL rejected'}
 $grants=$acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
 if ($grants.Count -eq 0){Deny 'empty ACL'}
 foreach($ace in $grants) {
  if($ace.IsInherited -or $ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or -not ($allowed -contains $ace.IdentityReference.Value)){
   Deny 'unexpected ACL trustee or rule'
  }
 }
}
function ProtectAcl([string]$path) {
 $self=[Security.Principal.WindowsIdentity]::GetCurrent().User
 $entry=if([IO.Directory]::Exists($path)){[IO.DirectoryInfo]::new($path)}else{[IO.FileInfo]::new($path)}
 $acl=$entry.GetAccessControl()
 $acl.SetOwner($self);$acl.SetAccessRuleProtection($true,$false)
 foreach($ace in @($acl.Access)) {[void]$acl.RemoveAccessRuleAll($ace)}
 foreach($sid in @($self,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
  $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.InheritanceFlags]::None,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
  $acl.AddAccessRule($rule)
 }
 $entry=if([IO.Directory]::Exists($path)){[IO.DirectoryInfo]::new($path)}else{[IO.FileInfo]::new($path)}
 $entry.SetAccessControl($acl)
 CheckAcl $path
}
function Entropy {
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 return [Text.Encoding]::UTF8.GetBytes('Ptah E07 canonical NodeRestartSeed v1|' + $sid)
}
$requestJson=[Console]::In.ReadToEnd()
if ($requestJson.Length -gt 131072 -or $requestJson.Length -eq 0){Deny 'request size refused'}
$request=ConvertFrom-Json -InputObject $requestJson
$path=CheckPath ([string]$request.path)
if ([string]::IsNullOrWhiteSpace($path)){Deny 'no path'}
$parent=[IO.Path]::GetDirectoryName($path)
CheckAcl $parent
switch ([string]$request.mode) {
 'protect' {
  ProtectAcl $path
  [Console]::Out.Write('{"status":"protected"}')
 }
 'check' {
  CheckAcl $path
  [Console]::Out.Write('{"status":"verified"}')
 }
 'read' {
  CheckAcl $path
  $bytes=[IO.File]::ReadAllBytes($path)
  if ($bytes.Length -lt 32 -or $bytes.Length -gt 65536){Deny 'sealed state length refused'}
  $plain=[Security.Cryptography.ProtectedData]::Unprotect($bytes,(Entropy),[Security.Cryptography.DataProtectionScope]::CurrentUser)
  if ($plain.Length -lt 10 -or $plain.Length -gt 65536){Deny 'decoded state length refused'}
  [Console]::Out.Write([Text.Encoding]::UTF8.GetString($plain))
 }
 'write' {
  CheckAcl $path
  $seed=[string]$request.seed
  if ($seed.Length -lt 10 -or $seed.Length -gt 65536){Deny 'invalid state payload size'}
  $plain=[Text.Encoding]::UTF8.GetBytes($seed)
  $sealed=[Security.Cryptography.ProtectedData]::Protect($plain,(Entropy),[Security.Cryptography.DataProtectionScope]::CurrentUser)
  $temporary=Join-Path $parent ('node-seed-stage-' + [guid]::NewGuid().ToString('N') + '.dpapi')
  $backup=Join-Path $parent ('node-seed-backup-' + [guid]::NewGuid().ToString('N') + '.dpapi')
  $committed=$false
  try {
   $stream=[IO.FileStream]::new($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
   try {$stream.Write($sealed,0,$sealed.Length);$stream.Flush($true)}finally{$stream.Dispose()}
   ProtectAcl $temporary
   [IO.File]::Replace($temporary,$path,$backup)
   $committed=$true
   CheckAcl $path
   [Console]::Out.Write('{"status":"written"}')
  } finally {
   if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}
   if([IO.File]::Exists($backup)){CheckAcl $backup;[IO.File]::Delete($backup)}
   if(-not $committed){[Console]::Error.Write('state update did not commit')}
  }
 }
 default {Deny 'unsupported custody operation'}
}
