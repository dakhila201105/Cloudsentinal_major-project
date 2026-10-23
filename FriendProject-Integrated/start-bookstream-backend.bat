@echo off
cd /d "%~dp0BookStream\backend"
if not exist node_modules npm install
npm run dev
