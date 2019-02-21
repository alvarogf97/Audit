pyinstaller ../../start.py --onefile --windowed --ico="../icon/icon.ico" --add-data ../../resources/certs;certs --add-data ../icon;icon  --uac-admin --noupx --hidden-import=sklearn.neighbors.typedefs
