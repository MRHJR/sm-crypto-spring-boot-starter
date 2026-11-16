@echo off
setlocal
rem Generates one SM2 private key locally. This script does not write or upload the key.
echo SM2 private key. Copy the next line into your local YAML. Keep it private.
"%SystemRoot%\System32\WindowsPowerShell1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; $hex='FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123'; $n=New-Object byte[] 32; $k=New-Object byte[] 32; for($i=0;$i -lt 32;$i++){ $n[$i]=[Convert]::ToByte($hex.Substring(2*$i,2),16) }; $rng=[System.Security.Cryptography.RandomNumberGenerator]::Create(); try { do { $rng.GetBytes($k); $nonzero=$false; $cmp=0; for($i=0;$i -lt 32;$i++){ if($k[$i] -ne 0){ $nonzero=$true }; if($cmp -eq 0){ $cmp=[int]$k[$i]-[int]$n[$i] } } } while(-not $nonzero -or $cmp -ge 0); [Console]::WriteLine([Convert]::ToBase64String($k).TrimEnd([char]'=').Replace('+','-').Replace('/','_')) } finally { [Array]::Clear($k,0,$k.Length); $rng.Dispose() }"
set "SM2_RESULT=%ERRORLEVEL%"
if not "%SM2_RESULT%"=="0" echo Key generation failed. Windows PowerShell is required.
echo.
echo Press any key to close.
pause >nul
exit /b %SM2_RESULT%
