<script setup>
</script>

<template>
  <section>
    <h2>Recommandations de sécurité</h2>
    <ul>
      <li>
        <div class="reco-title">Patching</div>
        Maintenez tous les systèmes, applications et équipements réseau à jour avec les derniers correctifs de sécurité fournis par les éditeurs. Un système non patché est vulnérable aux attaques connues. Mettez en place une politique de gestion des correctifs, automatisez l’application des mises à jour lorsque c’est possible, et vérifiez régulièrement l’état de vos systèmes pour détecter les failles non corrigées.
      </li>
      <li>
        <div class="reco-title">Configuration</div>
        Appliquez des configurations sécurisées par défaut et limitez les privilèges au strict nécessaire. Désactivez les comptes et services inutiles, changez les mots de passe par défaut, et appliquez le principe du moindre privilège pour les utilisateurs et les applications. Documentez et contrôlez toutes les modifications de configuration afin de garantir la cohérence et la sécurité de l’environnement.
      </li>
      <li>
        <div class="reco-title">Segmentation</div>
        Séparez les réseaux critiques (serveurs, bases de données, systèmes industriels) des réseaux utilisateurs ou invités. Utilisez des VLAN, des pare-feux et des listes de contrôle d’accès pour limiter la communication entre segments. Cette approche réduit la propagation d’une attaque et permet de mieux contrôler les flux de données sensibles.
      </li>
      <li>
        <div class="reco-title">Désactivation de services</div>
        Désactivez tous les services, ports et protocoles non utilisés sur vos systèmes et équipements réseau. Chaque service actif représente une porte d’entrée potentielle pour un attaquant. Faites régulièrement l’inventaire des services actifs et supprimez ceux qui ne sont pas strictement nécessaires au fonctionnement de l’organisation.
      </li>
      <li>
        <div class="reco-title">Bonnes pratiques</div>
        Utilisez des mots de passe forts et uniques pour chaque compte, activez l’authentification multi-facteur partout où c’est possible, surveillez les journaux d’activité pour détecter les comportements suspects, et formez régulièrement les utilisateurs aux risques de cybersécurité (phishing, ingénierie sociale, etc.). Sensibiliser les équipes est un élément clé pour renforcer la sécurité globale.
      </li>
    </ul>
  </section>
</template>

<style scoped>
ul {
  margin-top: 1rem;
  padding-left: 1.5rem;
}
li {
  margin-bottom: 1.5rem;
  list-style: none;
  border-bottom: 1px solid #eee;
  padding-bottom: 1rem;
}
.reco-title {
  text-align: center;
  font-weight: bold;
  font-size: 1.2rem;
  margin-bottom: 0.5rem;
  margin-top: 0.5rem;
  color: #2c3e50;
}
</style>
