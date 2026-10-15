@echo off
setlocal
cd /d "%~dp0"
set "MAVEN_CMD=mvn"
where mvn >nul 2>nul
if errorlevel 1 (
  set "MAVEN_CMD="
  for /d %%M in ("%LOCALAPPDATA%\Programs\Apache\Maven\apache-maven-*") do (
    if exist "%%~fM\bin\mvn.cmd" set "MAVEN_CMD=%%~fM\bin\mvn.cmd"
  )
)
if not defined MAVEN_CMD (
  echo Maven 3.9 or newer is required. Install Maven, then run this script again.
  exit /b 1
)
for /d %%J in ("%ProgramFiles%\Java\jdk-25*") do (
  if exist "%%~fJ\bin\javac.exe" set "JAVA_HOME=%%~fJ"
)
if not defined JAVA_HOME (
  echo Set JAVA_HOME to a Java 25 or newer JDK, then run this script again.
  exit /b 1
)
set "PATH=%JAVA_HOME%\bin;%PATH%"
call "%MAVEN_CMD%" clean package
