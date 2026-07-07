import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (!id.includes('node_modules')) return
          if (id.includes('swagger-ui')) return 'swagger'
          if (id.includes('recharts') || id.includes('/d3-') || id.includes('victory')) return 'charts'
          if (id.includes('react-router')) return 'router'
          if (id.includes('@radix-ui')) return 'radix'
          if (id.includes('lucide-react')) return 'icons'
          if (id.includes('@tanstack')) return 'query'
          if (id.includes('/react-dom/') || id.includes('/react/') || id.includes('/scheduler/')) return 'react'
          return 'vendor'
        },
      },
    },
  },
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
