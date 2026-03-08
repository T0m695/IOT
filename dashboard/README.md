
# Dashboard Vulnérabilités (Vue.js + Vite)

Ce projet frontend Vue.js consomme une API Flask disponible sur http://localhost:5000/donnees et affiche la liste des vulnérabilités dans une page dédiée.

## Fonctionnalités
- Récupération des vulnérabilités via l'API Flask
- Affichage sous forme de tableau dynamique
- Gestion des états de chargement et d'erreur

## Démarrage
1. Assurez-vous que l'API Flask tourne sur http://localhost:5000/donnees
2. Installez les dépendances :
	```bash
	npm install
	```
3. Lancez le serveur de développement :
	```bash
	npm run dev
	```
4. Accédez à l'application sur http://localhost:5173/

## Personnalisation
Le composant principal se trouve dans `src/components/Vulnerabilites.vue`.

---
Projet généré avec Vue 3 et Vite.
