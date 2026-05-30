@echo off

for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8000"') do taskkill /PID %%a /F
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8080"') do taskkill /PID %%a /F
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":9000"') do taskkill /PID %%a /F

echo All CASB services stopped.