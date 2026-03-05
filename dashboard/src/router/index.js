import { createRouter, createWebHistory } from 'vue-router'
import Vulnerabilites from '../components/Vulnerabilites.vue'
import Recommandations from '../components/Recommandations.vue'

const routes = [
  { path: '/', name: 'Vulnerabilites', component: Vulnerabilites },
  { path: '/recommandations', name: 'Recommandations', component: Recommandations }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router
