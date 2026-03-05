<script setup>
import { ref, onMounted } from 'vue'

const vulnerabilites = ref([])
const loading = ref(true)
const error = ref(null)

onMounted(async () => {
  try {
    const response = await fetch('http://localhost:5000/donnees')
    if (!response.ok) throw new Error('Erreur lors de la récupération des données')
    vulnerabilites.value = await response.json()
  } catch (err) {
    error.value = err.message
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <h2>Liste des vulnérabilités</h2>
    <div v-if="loading">Chargement...</div>
    <div v-else-if="error">Erreur : {{ error }}</div>
    <table v-else>
      <thead>
        <tr>
          <th v-for="(val, key) in vulnerabilites[0] || {}" :key="key">{{ key }}</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(item, idx) in vulnerabilites" :key="idx">
          <td v-for="(val, key) in item" :key="key">{{ val }}</td>
        </tr>
      </tbody>
    </table>
    <div v-if="!loading && vulnerabilites.length === 0">Aucune donnée trouvée.</div>
  </div>
</template>

<style scoped>
table {
  border-collapse: collapse;
  width: 100%;
}
th, td {
  border: 1px solid #ddd;
  padding: 8px;
}
th {
  background: #454545;
}
</style>
