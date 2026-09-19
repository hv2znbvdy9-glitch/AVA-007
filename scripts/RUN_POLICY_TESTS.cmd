@echo off
setlocal
cd /d "%~dp0\.."
python -m pytest tests\test_ava_policy_acceptance.py
if errorlevel 1 pause
