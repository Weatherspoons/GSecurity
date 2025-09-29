@echo off

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


