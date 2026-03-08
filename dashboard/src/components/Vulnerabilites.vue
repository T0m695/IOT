<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'

const vulnerabilites = ref([])
const loading = ref(true)
const error = ref(null)
const router = useRouter()

const goToDetail = (id) => {
  router.push({ name: 'VulnerabiliteDetail', params: { id } })
}


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

// Gradient de vert (0) à rouge (10) pour le score de priorité
function getPriorityColor(score) {
  // Clamp le score entre 0 et 10
  const s = Math.max(0, Math.min(10, Number(score)));
  // Interpolation linéaire du vert (#2ecc40) à rouge (#e74c3c)
  // Vert: rgb(46,204,64), Rouge: rgb(231,76,60)
  const r = Math.round(46 + (231 - 46) * (s / 10));
  const g = Math.round(204 + (76 - 204) * (s / 10));
  const b = Math.round(64 + (60 - 64) * (s / 10));
  return `rgb(${r},${g},${b})`;
}

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
  <div class="vuln-list-container">
    <h2>Liste des vulnérabilités</h2>
    <div v-if="loading" class="center">Chargement...</div>
    <div v-else-if="error" class="center error">Erreur : {{ error }}</div>
    <div v-else>
      <div v-if="vulnerabilites.length === 0" class="center">Aucune donnée trouvée.</div>
      <div v-else class="vuln-list">
        <div class="vuln-card" v-for="(item, idx) in vulnerabilites" :key="idx" @click="item.cve_id && goToDetail(item.cve_id)">
          <div class="vuln-header">
            <span class="vuln-id">{{ item.cve_id || item.id || 'ID inconnu' }}</span>
          </div>
          <div class="vuln-meta">
            <template v-for="(val, key) in item" :key="key">
              <span v-if="['cve_id','date_collecte'].includes(key)">
                <strong>{{ fieldLabels[key] || key }}:</strong> {{ val }}
              </span>
              <span v-else-if="key === 'priorite_score'" class="priority-highlight" :style="{ backgroundColor: getPriorityColor(val) }">
                <strong>{{ fieldLabels[key] || key }}:</strong> {{ val }}
              </span>
            </template>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
<style scoped>
.vuln-list-container {
  font-size: 1.2rem;
  margin: 2rem 0;
}
.error {
  color: #d32f2f;
}
.vuln-list {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
  max-width: 600px;
  margin: 0 auto;
}
.vuln-card {
  background: #fff;
  border-radius: 16px;
  box-shadow: 0 2px 16px rgba(0,0,0,0.10);
  padding: 1.5rem 1.5rem 1.2rem 1.5rem;
  cursor: pointer;
  transition: box-shadow 0.2s, transform 0.2s;
  border: 1px solid #e0e0e0;
  display: flex;
  flex-direction: column;
  gap: 0.7rem;
}
.vuln-card:hover {
  box-shadow: 0 4px 32px rgba(0,123,255,0.15);
  transform: translateY(-4px) scale(1.01);
  border-color: #0077ff;
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
.vuln-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 1.2rem;
  font-size: 1.04rem;
  color: #555;
}
strong {
  color: #0077ff;
}
.priority-highlight {
  border-radius: 6px;
  padding: 0.1em 0.5em;
  color: #222;
  font-weight: 600;
  box-shadow: 0 1px 4px rgba(0,0,0,0.04);
  display: inline-block;
}
</style>

