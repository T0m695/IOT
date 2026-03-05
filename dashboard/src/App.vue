<script setup>
import Vulnerabilites from './components/Vulnerabilites.vue'
</script>

<template>
  <nav style="margin-bottom: 2rem;">
    <router-link to="/">Vulnérabilités</router-link> |
    <router-link to="/recommandations">Recommandations</router-link>
  </nav>
  <main>
    <router-view />
  </main>
</template>

<style scoped>
main {
  padding: 2rem;
  font-family: Arial, sans-serif;
}
</style>
