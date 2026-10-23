@echo off
cd /d "%~dp0BookStream\frontend"
if not exist node_modules npm install
npm start
