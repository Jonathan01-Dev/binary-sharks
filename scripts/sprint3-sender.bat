@echo off
if  %~1== goto usage
setlocal
set FILE=%~1
pushd %~dp0\..
python main.py send %FILE%
python main.py start --port 7902 --share %FILE%
popd
goto end
:usage
echo Usage: sprint3-sender.bat <chemin\\vers\\fichier>
:end
