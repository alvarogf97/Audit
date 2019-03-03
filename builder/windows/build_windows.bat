pyinstaller ../../start.py --onefile --ico="../icon/icon.ico" --add-data ../../resources/certs;certs --add-data ../icon;icon  --uac-admin --noupx --clean --hidden-import=sklearn.neighbors.typedefs
