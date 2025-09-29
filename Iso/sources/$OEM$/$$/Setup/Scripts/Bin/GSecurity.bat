@echo off

:: Perms
takeown /f %windir%\System32\Oobe\useroobe.dll /A
icacls %windir%\System32\Oobe\useroobe.dll /reset
icacls %windir%\System32\Oobe\useroobe.dll /inheritance:r
icacls "%systemdrive%\Users" /remove "Everyone"
takeown /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c
icacls "%USERPROFILE%\Desktop" /remove "System" /t /c /l
icacls "%USERPROFILE%\Desktop" /remove "Administrators" /t /c /l
icacls "C:\Users\Public" /reset /T
takeown /f "C:\Users\Public\Desktop" /r /d y
icacls "C:\Users\Public\Desktop" /inheritance:r
icacls "C:\Users\Public\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c
icacls "C:\Users\Public\Desktop" /remove "System" /t /c /l
icacls "C:\Users\Public\Desktop" /remove "Administrators" /t /c /l
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


