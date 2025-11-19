@echo off  
cls  
echo ================================================================================  
echo NETWORK SECURITY MONITOR - EULA  
echo ================================================================================  
echo.  
echo [1] View Short EULA  
echo [2] View Full EULA  
echo [3] Accept and Continue  
echo [4] Exit  
echo.  
set /p choice=Choice:  
if %%choice%%==1 type EULA\EULA_Short.txt & pause & goto START  
if %%choice%%==2 start notepad EULA\End_User_License_Agreement.txt & pause & goto START  
if %%choice%%==3 goto START  
if %%choice%%==4 exit /b 1  
  
:START  
if exist ..\dist\NetworkSecurityMonitor.exe (  
