@echo off

where cmake >nul 2>nul
if %errorlevel% neq 0 (
    echo Cmake is not installed or found in system PATH.
    exit /b 1
)

where ninja >nul 2>nul
if %errorlevel% neq 0 (
    echo Ninja is not installed or found in system PATH.
    exit /b 1
)

:: Ensure the user has passed a build mode. 
if "%~1"=="" (
    echo Please specify a debug or release build ^(eg. .\build.bat Debug^)
    exit /b 1
)

mkdir build
cd build

set "BUILD_TYPE=%~1"

if /I "%BUILD_TYPE%"=="DEBUG" (
    echo Building in Debug mode
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug ..
) else if /I "%BUILD_TYPE%"=="RELEASE" (
    echo Building in Release mode
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release ..
) else (
    echo Invalid argument. Use DEBUG or RELEASE.
)

echo Building LiBurn-Payload
cmake --build . --target LiBurn-Payload

echo Converting the payload to shellcode
cd ..
python code_generator.py

echo Building LiBurn
cd build
cmake --build . --target LiBurn
