import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'
import fs from 'fs'

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'copy-openapi-specs',
      buildStart() {
        const src = path.resolve(__dirname, '../../api/openapi')
        const dest = path.resolve(__dirname, 'public/api-specs')
        if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true })
        if (fs.existsSync(src)) {
          for (const file of fs.readdirSync(src)) {
            if (file.endsWith('.yaml')) {
              fs.copyFileSync(path.join(src, file), path.join(dest, file))
            }
          }
        }
      },
    },
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api/': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
