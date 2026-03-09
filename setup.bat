@echo off

echo   INITIALISATION DU PROJET VULNERABILITES IOT

echo  Installation des modules Python...
pip install requests


echo  Recuperation de l'historique 
python fetch_all_time.py


echo  Configuration de la recuperation a 00h01 tout les jours
schtasks /create /tn "MAJ_Quotidienne_IoT" /tr "python.exe '%~dp0fetch.py'" /sc daily /st 00:01 /f


echo   TERMINE !

pause