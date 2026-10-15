# E07 Windows Node identity custody: isolated DPAPI and ACL qualification.
# Explicitly non-authorizing: self-test only; never provisions a production Node.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string] $Root,
    [switch] $SelfTest
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-True([bool]$Condition, [string]$Reason) {
    if (-not $Condition) { throw $Reason }
}
function Assert-SafePath([string]$Path) {
    Assert-True ([IO.Path]::IsPathRooted($Path)) "Absolute state path required"
    $resolved = [IO.Path]::GetFullPath($Path)
    $current = $resolved
    while ($current) {
        if ([IO.File]::Exists($current) -or [IO.Directory]::Exists($current)) {
            $attrs = [IO.File]::GetAttributes($current)
            Assert-True (($attrs -band [IO.FileAttributes]::ReparsePoint) -eq 0) "Reparse point in state path"
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $current) { break }
        $current = $parent
    }
}
function Secure-Acl([string]$Path, [bool]$Directory) {
    $principal = [Security.Principal.WindowsIdentity]::GetCurrent()
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetOwner($principal.User)
    $acl.SetAccessRuleProtection($true, $false)
    foreach($ace in @($acl.Access)){ [void]$acl.RemoveAccessRuleAll($ace) }
    $allowed = @(
        $principal.User,
        [Security.Principal.SecurityIdentifier]::new("S-1-5-18"),
        [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    )
    $inherit = if ($Directory) { [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit }
               else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($sid in $allowed) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            $inherit, [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Check-Acl([string]$Path) {
    Assert-SafePath $Path
    $acl=Get-Acl -LiteralPath $Path
    Assert-True $acl.AreAccessRulesProtected "Inherited permissions are not allowed"
    $selfSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowed=@($selfSid,"S-1-5-18","S-1-5-32-544")
    Assert-True ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $selfSid) "Owner differs"
    $grants = $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
    Assert-True ($grants.Count -gt 0) "Missing protected access rules"
    foreach ($ace in $grants) {
        Assert-True (-not $ace.IsInherited) "Inherited access"
        Assert-True ($ace.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) "Unexpected deny rule"
        Assert-True ($allowed -contains $ace.IdentityReference.Value) "Unexpected trustee"
        Assert-True (($ace.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl) "Incomplete allowed rights"
    }
}
function Protect-State([byte[]]$Bytes,[string]$File) {
    Add-Type -AssemblyName System.Security
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $entropy=[Text.Encoding]::UTF8.GetBytes("Ptah E07 isolated Node seed v1|$owner")
    $sealed = [Security.Cryptography.ProtectedData]::Protect(
        $Bytes,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    $stream=[IO.FileStream]::new($File,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try { $stream.Write($sealed,0,$sealed.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    Secure-Acl $File $false
    Check-Acl $File
}
function Verify-State([string]$File) {
    Check-Acl $File
    $bytes=[IO.File]::ReadAllBytes($File)
    Assert-True ($bytes.Length -gt 32 -and $bytes.Length -lt 65536) "Protected state size out of bounds"
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $entropy=[Text.Encoding]::UTF8.GetBytes("Ptah E07 isolated Node seed v1|$owner")
    $clear=[Security.Cryptography.ProtectedData]::Unprotect(
        $bytes,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    return $clear
}
if (-not $SelfTest) { throw "This tool only supports disposable custody self-test; production enrollment is not provisioned." }
Assert-SafePath $Root
Assert-True (-not (Test-Path -LiteralPath $Root)) "Self-test root must not preexist"
[void][IO.Directory]::CreateDirectory($Root)
Secure-Acl $Root $true
Check-Acl $Root
$source=New-Object byte[] 64
$rng = [Security.Cryptography.RNGCryptoServiceProvider]::new()
try { $rng.GetBytes($source) } finally { $rng.Dispose() }
$state = Join-Path $Root "e07-disposable-node-seed.dpapi"
Protect-State $source $state
$plain=Verify-State $state
Assert-True (([Convert]::ToBase64String($source) -ceq [Convert]::ToBase64String($plain))) "DPAPI round-trip mismatch"
$raw=[IO.File]::ReadAllBytes($state)
Assert-True (-not ([Convert]::ToBase64String($source) -ceq [Convert]::ToBase64String($raw))) "Plaintext exposure"
$raw[$raw.Length-1]=$raw[$raw.Length-1] -bxor 1
[IO.File]::WriteAllBytes($state,$raw)
$rejected=$false
try { [void](Verify-State $state) } catch { $rejected=$true }
Assert-True $rejected "Tampered ciphertext was accepted"
[pscustomobject]@{
    schema = "ptah.e07.windows-custody-disposable-selftest.v1"
    status = "PASS"
    dpapi_current_user = $true
    restrictive_acl = $true
    tamper_rejected = $true
    production_enrollment = $false
    location = $Root
} | ConvertTo-Json -Compress
