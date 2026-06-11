@echo off
setlocal

set API_JAR=lib\montoya-api-2026.4.jar
set SRC_DIR=src\main\java
set OUT_DIR=build\classes
set JAR_NAME=xia_tan-2.0.jar

echo [*] xia_tan v2.0 build script (Montoya API)

:: Download Montoya API if not present
if not exist lib mkdir lib
if not exist "%API_JAR%" (
    echo [*] Downloading Montoya API 2026.4...
    powershell -Command "Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2026.4/montoya-api-2026.4.jar' -OutFile '%API_JAR%'"
    if errorlevel 1 (
        echo [!] Failed to download API. Please manually place montoya-api-2026.4.jar in lib/
        exit /b 1
    )
    echo [+] API downloaded.
)

:: Clean and compile
if exist "%OUT_DIR%" rmdir /s /q "%OUT_DIR%"
mkdir "%OUT_DIR%"

echo [*] Finding source files...
dir /s /b "%SRC_DIR%\*.java" > sources.txt

echo [*] Compiling with Montoya API...
javac --release 8 -cp "%API_JAR%" -d "%OUT_DIR%" -encoding UTF-8 @sources.txt
if errorlevel 1 (
    echo [!] Compilation failed!
    del sources.txt
    exit /b 1
)
del sources.txt
echo [+] Compilation successful.

:: Package JAR
if not exist build\libs mkdir build\libs
echo [*] Packaging JAR...
jar cf "build\libs\%JAR_NAME%" -C "%OUT_DIR%" burp
if not exist "build\libs\%JAR_NAME%" (
    cd "%OUT_DIR%"
    jar cf "..\libs\%JAR_NAME%" burp\*.class burp\injection\*.class burp\util\*.class
    cd ..\..
)

echo [+] Build complete: build\libs\%JAR_NAME%
echo [*] Load in BurpSuite (>=2023.12.1): Extender ^> Add ^> Java ^> Select JAR
