@echo off
REM Build Nim parser to native binary

echo Building nim_parser...

cd /d "%~dp0\.."

nim c -d:release --opt:speed --out:app\parsers\nim_parser.exe app\parsers\nim_parser.nim

if %ERRORLEVEL% == 0 (
    echo.
    echo Build successful: app\parsers\nim_parser.exe
    echo.
    echo Test run:
    app\parsers\nim_parser.exe --help
) else (
    echo.
    echo Build failed. Make sure Nim is installed:
    echo   winget install nim-lang.Nim
    echo   or download from https://nim-lang.org/install.html
)

pause
