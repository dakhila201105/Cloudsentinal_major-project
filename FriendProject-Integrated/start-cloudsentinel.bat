@echo off
cd /d "%~dp0CloudSentinel"
if not exist venv\Scripts\python.exe python -m venv venv
call venv\Scripts\activate.bat
if not exist .deps-installed type nul > .deps-installed && pip install -r requirements.txt
python app.py
