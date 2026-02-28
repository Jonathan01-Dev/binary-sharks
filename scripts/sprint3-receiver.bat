@echo off
if  %~1== goto usage
setlocal
set MANIFEST=%~1
pushd %~dp0\..
python main.py download %MANIFEST% --port 7902 --wait-seconds 10 --output-dir demo\\tmp_sprint3_test\\downloads
popd
goto end
:usage
echo Usage: sprint3-receiver.bat <chemin\\vers\\manifeste.json>
:end
