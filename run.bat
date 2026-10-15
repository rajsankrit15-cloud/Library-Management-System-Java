@echo off
setlocal
cd /d "%~dp0"
for /d %%J in ("%ProgramFiles%\Java\jdk-25*") do (
  if exist "%%~fJ\bin\java.exe" set "JAVA_HOME=%%~fJ"
)
if not defined JAVA_HOME (
  echo Set JAVA_HOME to a Java 25 or newer JDK, then run this script again.
  exit /b 1
)
set "PATH=%JAVA_HOME%\bin;%PATH%"
set "APP_JAR=target\library-management-system-1.0.0.jar"
if not exist "%APP_JAR%" (
  echo Application JAR not found. Build it first with: mvn clean package
  exit /b 1
)
java -jar "%APP_JAR%"
