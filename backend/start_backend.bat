@echo off
title PhishShield AI - Forensic Defense Microservice
echo ============================================================
echo   PhishShield AI: Local Forensic Defense Microservice
echo   Target: http://127.0.0.1:8000
echo ============================================================
cd /d "%~dp0"
python -m uvicorn app:app --host 127.0.0.1 --port 8000 --reload
pause
