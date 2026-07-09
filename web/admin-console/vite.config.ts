import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // NOTE: custom manualChunks removed — isolating react/react-dom into a separate
  // chunk from its consumers (radix/router/query/charts/swagger/vendor) caused
  // "Cannot read properties of undefined (reading 'useLayoutEffect')" at runtime
  // when a consumer chunk initialised before the react chunk. Vite's default
  // chunking orders React correctly. Reintroduce splitting only if browser-verified.
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
