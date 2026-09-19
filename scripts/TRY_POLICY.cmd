@echo off
setlocal
cd /d "%~dp0\.."
python -m ava.policy_cli %*
