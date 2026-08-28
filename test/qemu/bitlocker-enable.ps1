# Enable BitLocker on C: from an elevated (SYSTEM) shell inside the PBA-booted Windows.
# Reports over COM1 (host serial log). The TPM protector gives auto-unlock; a recovery
# password is added as a fallback. The offline-applied demo image never provisioned the
# TPM, so we take ownership first, and we wait for FullyEncrypted (protection engages at
# 100%) before a clean shutdown.
$ErrorActionPreference = 'Continue'
function Com($m){
  Write-Host "BL: $m"
  try { $p=[System.IO.Ports.SerialPort]::new('COM1',115200,'None',8,'One'); $p.Open(); $p.WriteLine("BL: $m"); $p.Close() } catch {}
}
Com "start user=$([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
try { Com ("secureboot=" + (Confirm-SecureBootUEFI)) } catch { Com "sb? $_" }

# BitLocker requires an OWNED TPM ("The TPM does not have an owner set" otherwise).
$t0 = Get-Tpm
Com "tpm present=$($t0.TpmPresent) ready=$($t0.TpmReady) owned=$($t0.TpmOwned)"
if (-not $t0.TpmOwned) {
  try { Initialize-Tpm -ErrorAction Stop | Out-Null; Com "Initialize-Tpm ok" }
  catch { $m="$($_.Exception.Message)"; if($m.Length -gt 90){$m=$m.Substring(0,90)}; Com "init-tpm err: $m" }
  Start-Sleep -Seconds 4
  $t1 = Get-Tpm; Com "after-init owned=$($t1.TpmOwned)"
}

# TPM protector = primary auto-unlock; -SkipHardwareTest + Resume-BitLocker so protection
# engages without a reboot. Retry across TPM-provisioning settling.
$ok = $false
for ($r=0; $r -lt 15 -and -not $ok; $r++) {
  try {
    Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes128 -UsedSpaceOnly -TpmProtector -SkipHardwareTest -ErrorAction Stop | Out-Null
    Com "enable OK (TpmProtector, retry $r)"; $ok = $true
  } catch { $m="$($_.Exception.Message)"; if($m.Length -gt 70){$m=$m.Substring(0,70)}; Com "enable retry ${r} - $m"; Start-Sleep -Seconds 5 }
}
try { Add-BitLockerKeyProtector -MountPoint C: -RecoveryPasswordProtector -ErrorAction Stop | Out-Null } catch {}
try { Resume-BitLocker -MountPoint C: -ErrorAction Stop | Out-Null; Com "Resume-BitLocker done" } catch { Com "resume err: $_" }
$rp = (Get-BitLockerVolume -MountPoint C:).KeyProtector | ?{$_.KeyProtectorType -eq 'RecoveryPassword'}
Com "recovery-password=$($rp.RecoveryPassword)"

# Wait for FullyEncrypted + protection On (used-space-only is quick on a fresh install).
for ($i=0; $i -lt 90; $i++) {
  $v = Get-BitLockerVolume -MountPoint C:
  Com "poll $i status=$($v.VolumeStatus) prot=$($v.ProtectionStatus) pct=$($v.EncryptionPercentage)"
  if ($v.ProtectionStatus -eq 'On' -and $v.VolumeStatus -eq 'FullyEncrypted') { break }
  Start-Sleep -Seconds 5
}
$v = Get-BitLockerVolume -MountPoint C:
Com "FINAL status=$($v.VolumeStatus) protection=$($v.ProtectionStatus) pct=$($v.EncryptionPercentage)"
foreach ($kp in $v.KeyProtector) { Com "protector: $($kp.KeyProtectorType)" }
Com "DONE"
Start-Sleep -Seconds 3
& shutdown /s /t 2 /f
