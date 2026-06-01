import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const apiTarget = process.env.BONGSU_API_TARGET || 'http://localhost:8080'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': apiTarget,
    },
  },
})
