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
