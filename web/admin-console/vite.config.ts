import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'

// Vite 8's native loader does not inject CommonJS __dirname (see
// vitest.config.ts); derive it the same way so the plugin below resolves the
// same directory under both loaders.
const here = path.dirname(fileURLToPath(import.meta.url))

// The API-docs page (src/pages/api-docs.tsx) renders /api-specs/<name>.yaml.
// Those used to be ten checked-in files under public/api-specs/ that a comment
// called "copied from api/openapi by the build". Nothing copied them: they
// were hand-written, stamped 0.1.0, last touched 2026-08-24, and each held a
// fraction of the routes the canonical spec holds (access: 49 paths against
// 267). Three of the ten were not even listed on the page. So the console
// served a stale subset of the API and said it was the API.
//
// This plugin makes the comment true: in `vite dev` the specs are served from
// api/openapi/ directly, and `vite build` copies them into dist/api-specs/.
// Nothing is checked in twice. A missing directory is an error, not an empty
// list, because an API-docs page with no specs would otherwise render green.
// The Docker build copies api/openapi/ to /api/openapi/, which is what
// ../../api/openapi resolves to from /app.
const SPEC_DIR = path.resolve(here, '../../api/openapi')
function openapiSpecs(): Plugin {
  const list = () => {
    if (!fs.existsSync(SPEC_DIR)) {
      throw new Error(`openapi specs: ${SPEC_DIR} does not exist; the API-docs page would publish nothing`)
    }
    const files = fs.readdirSync(SPEC_DIR).filter((f) => f.endsWith('.yaml'))
    if (files.length === 0) throw new Error(`openapi specs: no *.yaml under ${SPEC_DIR}`)
    return files
  }
  let outDir = 'dist'
  return {
    name: 'openidx-openapi-specs',
    configResolved(config) {
      outDir = config.build.outDir
    },
    configureServer(server) {
      server.middlewares.use('/api-specs', (req, res, next) => {
        const name = path.basename(decodeURIComponent((req.url ?? '/').split('?')[0]))
        if (!name.endsWith('.yaml') || !list().includes(name)) return next()
        res.setHeader('Content-Type', 'application/yaml; charset=utf-8')
        fs.createReadStream(path.join(SPEC_DIR, name)).pipe(res)
      })
    },
    closeBundle() {
      const dst = path.resolve(here, outDir, 'api-specs')
      fs.mkdirSync(dst, { recursive: true })
      for (const f of list()) fs.copyFileSync(path.join(SPEC_DIR, f), path.join(dst, f))
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), openapiSpecs()],
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
    // 3000, not 5173. The seeded admin-console OAuth client registers
    // http://localhost:3000/login and /callback, and OAUTH_LOGIN_URL defaults
    // to http://localhost:3000/login -- so on 5173 the sign-in round trip ends
    // at "redirect_uri not registered for client" and there is no way to log
    // in at all. e2e/README.md has documented :3000 all along; this file was
    // the odd one out.
    port: 3000,
    // Fail rather than silently moving to 3001, which would break the redirect
    // URI in a way that looks like a server bug.
    strictPort: true,
    // Dev proxy = the deployed edge route table.
    //
    // In a deployment nginx sends /api/v1/ to APISIX, which forwards each
    // prefix to one service and everything else to admin-api via an /api/*
    // catch-all (deployments/apisix-edge/seed-edge-routes.sh). This list used
    // to be a hand-written subset of that: identity, governance, provisioning,
    // audit, and three admin-api paths spelled out one at a time. Everything
    // else -- /api/v1/access/* (PAM, Ziti, devices, quick links), /oauth/*
    // (the login the SPA posts to), and the whole admin-api surface behind the
    // catch-all: ISPM, privacy, analytics, vault, social providers, AI agents
    // -- had no rule, so `npm run dev` answered 404 for most of the console
    // and the only way to develop against a local stack was not to.
    //
    // Order matters: Vite matches keys in insertion order, so the specific
    // prefixes come first and '/api/' is last, exactly like the edge router's
    // priorities. tools/contractcheck/edge.go holds the same map for the
    // response-shape gate, pinned to the seed script by its own test.
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
        ws: true,
      },
      '/api/v1/access': {
        target: 'http://localhost:8007',
        changeOrigin: true,
        ws: true,
      },
      '/api/v1/oauth': {
        target: 'http://localhost:8006',
        changeOrigin: true,
      },
      '/api/v1/saml': {
        target: 'http://localhost:8006',
        changeOrigin: true,
      },
      // The SPA's own login/token calls, and OIDC discovery.
      '/oauth': {
        target: 'http://localhost:8006',
        changeOrigin: true,
      },
      '/.well-known': {
        target: 'http://localhost:8006',
        changeOrigin: true,
      },
      // The catch-all, last: everything else under /api/ is admin-api.
      '/api/': {
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
