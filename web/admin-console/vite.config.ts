import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'
import fs from 'fs'

export default defineConfig(({ mode }) => {
  const isProduction = mode === 'production'

  return {
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
    // Production build configuration
    build: isProduction ? {
      outDir: 'dist',
      assetsDir: 'assets',
      sourcemap: false,
      minify: 'esbuild',
      target: 'es2015',
      rollupOptions: {
        output: {
          manualChunks: {
            'react-vendor': ['react', 'react-dom', 'react-router-dom'],
            'ui-vendor': ['@radix-ui/react-dialog', '@radix-ui/react-dropdown-menu', '@radix-ui/react-select'],
            'query-vendor': ['@tanstack/react-query'],
          },
          assetFileNames: 'assets/[name]-[hash][extname]',
          chunkFileNames: 'assets/[name]-[hash].js',
          entryFileNames: 'assets/[name]-[hash].js',
        },
      },
      chunkSizeWarningLimit: 1000,
    } : undefined,
    // Base path for production deployment
    base: isProduction ? '/' : '/',
    // Define global constants
    define: isProduction ? {
      '__APP_VERSION__': JSON.stringify(process.env.npm_package_version || '1.0.0'),
      '__BUILD_DATE__': JSON.stringify(new Date().toISOString()),
    } : {},
  }
})
