#!/usr/bin/env bash
pyinstaller ../../start.py --onefile --windowed --ico="../icon/icon.ico" --add-data ../../resources/certs:certs --add-data ../icon:icon --add-data ../../resources/scripts:scripts --uac-admin --noupx --windowed
