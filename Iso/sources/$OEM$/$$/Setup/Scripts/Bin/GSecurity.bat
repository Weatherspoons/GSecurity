@echo off

:: Perms
takeown /f %windir%\System32\Oobe\useroobe.dll /A
icacls %windir%\System32\Oobe\useroobe.dll /reset
icacls %windir%\System32\Oobe\useroobe.dll /inheritance:r
icacls "%systemdrive%\Users" /remove "Everyone"
takeown /f "%USERPROFILE%\Desktop" /A /R /D y
icacls "%USERPROFILE%\Desktop" /reset
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /grant:r "*S-1-2-1:F" /t /l /q /c
takeown /f "C:\Users\Public\Desktop" /A /R /D y
icacls "C:\Users\Public\Desktop" /reset
icacls "C:\Users\Public\Desktop" /inheritance:r
icacls "C:\Users\Public\Desktop" /grant:r "*S-1-2-1:F" /t /l /q /c
takeown /f "C:\Windows\System32\wbem" /A
icacls "C:\Windows\System32\wbem" /reset
icacls "C:\Windows\System32\wbem" /inheritance:r

:: Services
sc config seclogon start= disabled
sc stop seclogon

:: Users
net user defaultuser0 /delete

:: Registry
for /f "tokens=*" %%C in ('dir /b /o:n *.reg') do (
    reg import "%%C"
)

:: Restart
shutdown /r /t 0


