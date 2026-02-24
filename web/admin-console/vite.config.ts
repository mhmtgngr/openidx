import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api/v1/identity': {
        target: 'http://localhost:8001',
        changeOrigin: true,
      },
      '/api/v1/governance': {
        target: 'http://localhost:8002',
        changeOrigin: true,
      },
      '/api/v1/provisioning': {
        target: 'http://localhost:8003',
        changeOrigin: true,
      },
      '/api/v1/audit': {
        target: 'http://localhost:8004',
        changeOrigin: true,
      },
      '/api/v1/dashboard': {
        target: 'http://localhost:8005',
        changeOrigin: true,
      },
      '/api/v1/settings': {
        target: 'http://localhost:8005',
        changeOrigin: true,
      },
      '/api/v1/applications': {
        target: 'http://localhost:8005',
        changeOrigin: true,
      },
      '/scim/v2': {
        target: 'http://localhost:8003',
        changeOrigin: true,
      },
    },
  },
})
