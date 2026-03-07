<script setup>
import { useRoute } from 'vue-router'
import { ref, onMounted } from 'vue'

const route = useRoute()
const id = route.params.id
const vuln = ref(null)
const loading = ref(true)
const error = ref(null)

// Correspondance clé -> label
const fieldLabels = {
  cve_id: 'CVE',
  cvss_impact: 'Score CVSS',
  cwe: 'ID CWE',
  date_collecte: 'Date de collecte',
  description: 'Description',
  epss_prob: 'Probabilité EPSS',
  kev_actif: 'KEV actif',
  priorite_score: 'Score de priorité'
}

onMounted(async () => {
  try {
    const response = await fetch('http://localhost:5000/donnees')
    if (!response.ok) throw new Error('Erreur lors de la récupération des données')
    const data = await response.json()
    vuln.value = data.find(v => v.cve_id == id)
  } catch (err) {
    error.value = err.message
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="vuln-list-container">
    <div v-if="loading" class="center">Chargement...</div>
    <div v-else-if="error" class="center error">Erreur : {{ error }}</div>
    <div v-else-if="!vuln" class="center">Vulnérabilité non trouvée.</div>
    <div v-else class="vuln-card vuln-detail-card">
      <div class="vuln-header">
        <span class="vuln-id">{{ vuln.cve_id || vuln.id || 'ID inconnu' }}</span>
        <span class="vuln-title">{{ vuln.nom || vuln.titre || 'Vulnérabilité' }}</span>
      </div>
      <div class="vuln-meta vuln-detail-meta">
        <span v-for="(val, key) in vuln" :key="key">
            <span v-if="key !== 'description'">
                <strong>{{ fieldLabels[key] || key }}:</strong> {{ val }}
            </span>
        </span>
      </div>
      <div class="vuln-desc vuln-detail-desc">{{ vuln.description || vuln.desc || 'Pas de description.' }}</div>
    </div>
  </div>
</template>


<style scoped>
.vuln-list-container {
  font-family: Arial, sans-serif;
  min-height: 60vh;
  padding: 2rem 0;
  display: flex;
  align-items: center;
  justify-content: center;
}
.center {
  text-align: center;
  font-size: 1.2rem;
  margin: 2rem 0;
}
.error {
  color: #d32f2f;
}
.vuln-card {
  background: #fff;
  border-radius: 16px;
  box-shadow: 0 2px 16px rgba(0,0,0,0.10);
  padding: 1.5rem 1.5rem 1.2rem 1.5rem;
  border: 1px solid #e0e0e0;
  display: flex;
  flex-direction: column;
  gap: 0.7rem;
  max-width: 600px;
  width: 100%;
}
.vuln-header {
  display: flex;
  gap: 1.2rem;
  align-items: center;
  margin-bottom: 0.2rem;
}
.vuln-id {
  font-size: 1.1rem;
  color: #0077ff;
  font-weight: bold;
  letter-spacing: 1px;
}
.vuln-title {
  font-size: 1.2rem;
  font-weight: bold;
  color: #2c3e50;
}
.vuln-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 1.2rem;
  font-size: 1.04rem;
  color: #555;
}
.vuln-desc {
  color: #444;
  font-size: 1.08rem;
  margin-bottom: 0.5rem;
}
strong {
  color: #0077ff;
}
.vuln-detail-card {
  margin: 0 auto;
  min-width: 320px;
}
.vuln-detail-meta {
  margin-bottom: 1rem;
}
.vuln-detail-desc {
  font-style: italic;
  color: #2c3e50;
  background: #f3f7ff;
  border-radius: 8px;
  padding: 0.7rem 1rem;
}
</style>
