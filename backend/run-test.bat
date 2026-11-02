@echo off
REM run-test.bat
REM Double-click this file (or run it from cmd) to test the encryption /
REM decryption flow. It just runs test-encryption.js and keeps the window
REM open afterward so you can read the output.
REM
REM BEFORE RUNNING:
REM   1. Make sure the backend is already running in ANOTHER window
REM      (cd backend && npm start) — this script talks to it over HTTP.
REM   2. Open test-encryption.js and set ADMIN_EMAIL / ADMIN_PASSWORD to
REM      your real admin login.

cd /d "%~dp0"
node test-encryption.js

echo.
echo ============================================================
echo Done. Look above for "--- 4. Decrypting via POST ..." ---
echo That section shows the ORIGINAL decrypted values.
echo ============================================================
pause
