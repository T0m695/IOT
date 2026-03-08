
import { createRouter, createWebHistory } from 'vue-router'
import Vulnerabilites from '../components/Vulnerabilites.vue'
import Recommandations from '../components/Recommandations.vue'
import VulnerabiliteDetail from '../components/VulnerabiliteDetail.vue'

const routes = [
  { path: '/', name: 'Vulnerabilites', component: Vulnerabilites },
  { path: '/recommandations', name: 'Recommandations', component: Recommandations },
  { path: '/vulnerabilite/:id', name: 'VulnerabiliteDetail', component: VulnerabiliteDetail, props: true }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router