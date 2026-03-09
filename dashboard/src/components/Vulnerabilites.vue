<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'


const vulnerabilites = ref([])
const loading = ref(true)
const error = ref(null)
const router = useRouter()


// Pour gérer le tri
const sortMode = ref('original') // 'original', 'date', 'cve_id'
const originalVulns = ref([])

const goToDetail = (id) => {
  router.push({ name: 'VulnerabiliteDetail', params: { id } })
}


function setSort(mode) {
  sortMode.value = mode
  if (mode === 'date') {
    vulnerabilites.value = [...originalVulns.value].sort((a, b) => {
      return new Date(b.date_collecte) - new Date(a.date_collecte)
    })
  } else if (mode === 'cve_id') {
    vulnerabilites.value = [...originalVulns.value].sort((a, b) => {
      // Tri alphanumérique croissant sur cve_id
      if (!a.cve_id) return 1;
      if (!b.cve_id) return -1;
      return a.cve_id.localeCompare(b.cve_id);
    })
  } else {
    vulnerabilites.value = [...originalVulns.value]
  }
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
    const data = await response.json()
    vulnerabilites.value = data
    originalVulns.value = [...data]
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
      <div class="sort-btn-group">
        <button @click="setSort('original')" class="sort-btn" :class="{ active: sortMode === 'original' }">Ordre d'origine</button>
        <button @click="setSort('date')" class="sort-btn" :class="{ active: sortMode === 'date' }">Trier par date</button>
        <button @click="setSort('cve_id')" class="sort-btn" :class="{ active: sortMode === 'cve_id' }">Trier par CVE</button>
      </div>
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

.sort-btn-group {
  display: flex;
  gap: 0.7rem;
  margin-bottom: 1.2rem;
}
.sort-btn {
  padding: 0.5em 1.2em;
  background: #0077ff;
  color: #fff;
  border: none;
  border-radius: 8px;
  font-size: 1rem;
  cursor: pointer;
  transition: background 0.2s, box-shadow 0.2s;
  outline: none;
}
.sort-btn.active, .sort-btn:focus {
  background: #005bb5;
  box-shadow: 0 0 0 2px #0077ff44;
}
.sort-btn:hover {
  background: #005bb5;
}

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

