@echo off

:: Import group and security policy
lgpo /g %~dp0

:: Import security policy
lgpo /s %~dp0GSecurity.inf