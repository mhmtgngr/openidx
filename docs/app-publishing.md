# App Publishing

App Publishing lets administrators register internal web applications, auto-discover their paths and endpoints, classify each path by security level, and publish them as proxy routes with per-path authorization policies.

## Overview

Publishing an internal app through OpenIDX follows five progressive security levels:

| Level | Approach | What It Provides |
|-------|----------|-----------------|
| 1 | **Reverse Proxy + Forward Auth** | Basic proxy with per-route authentication checks |
| 2 | **APISIX Route-Level Policies** | Gateway-enforced auth, rate limiting, IP restrictions |
| 3 | **OPA Policy Engine** | Fine-grained ABAC/RBAC policies per path |
| 4 | **Proxy Routes + Auto-Discovery** | Automatic endpoint scanning with classification-based policies |
| 5 | **OpenZiti Zero-Trust** | Full zero-trust overlay network, no exposed ports |

The App Publish feature implements **Level 4** and optionally enables **Level 5** (Ziti/BrowZer) during publishing.

## How It Works

### 1. Register an Application

Provide the app name, internal target URL, and optionally an OpenAPI spec URL.

```
POST /api/v1/access/apps
{
  "name": "HR Portal",
  "target_url": "http://hr-app:8080",
  "spec_url": "http://hr-app:8080/openapi.json",
  "description": "Employee management system"
}
```

### 2. Run Discovery

Discovery scans the target application using four strategies (in order):

1. **OpenAPI/Swagger** - Parses `spec_url` or probes well-known spec paths (`/openapi.json`, `/swagger.json`, `/api-docs`, etc.)
2. **Common Path Probing** - Sends HEAD requests to ~20 well-known paths (`/admin`, `/api`, `/health`, `/login`, `/settings`, `/dashboard`, `/docs`, `/metrics`, `/graphql`, etc.)
3. **Sitemap/robots.txt** - Parses `/sitemap.xml` and `/robots.txt` for additional paths
4. **HTML Link Crawl** - Extracts same-host `<a href>` links from the root page (max depth 1)

```
POST /api/v1/access/apps/{id}/discover
```

Discovery runs asynchronously. Poll the app or paths endpoint to track progress.

### 3. Review Classifications

Each discovered path is auto-classified into one of four security levels:

| Classification | Path Patterns | Default Policy |
|---------------|--------------|----------------|
| **Critical** | `/admin*`, `/settings*`, `/system*`, any `DELETE` | Auth required, admin role, device trust |
| **Sensitive** | `/api/*/users`, `/api/*/keys`, `/api/*/tokens`, `/api/*/secrets` | Auth required, admin role |
| **Protected** | Everything else (default) | Auth required, any authenticated user |
| **Public** | `/`, `/health*`, `/login`, `/docs*`, `/static*`, `/assets*`, `/favicon.ico`, `/robots.txt` | No auth required |

Classifications can be overridden manually. Manual overrides are preserved when re-running discovery.

### 4. Publish as Proxy Routes

Select paths and publish them. Each path becomes a proxy route with authorization policies based on its classification:

```
POST /api/v1/access/apps/{id}/publish
{
  "path_ids": ["uuid1", "uuid2"],
  "enable_ziti": false,
  "enable_browzer": false
}
```

Options:
- **enable_ziti** - Create OpenZiti service for zero-trust network overlay
- **enable_browzer** - Enable BrowZer for clientless browser access

## Admin Console Guide

### Navigating to App Publish

1. Log in as an admin
2. In the sidebar, under **Network & Access**, click **App Publish**

### Registering an App

1. Click **Register App**
2. Fill in the form:
   - **Name** - Display name for the application
   - **Target URL** - Internal URL where the app is running (e.g., `http://internal-app:8080`)
   - **OpenAPI Spec URL** (optional) - URL to an OpenAPI/Swagger spec for better discovery
   - **Description** (optional) - What the app does
3. Click **Register**

### Running Discovery

1. On the **Apps** tab, find your app card
2. Click **Discover** to start scanning
3. The card shows a spinning indicator while discovery runs
4. Once complete, the card shows how many paths were found and which strategies succeeded

### Reviewing and Editing Classifications

1. Click **Paths** on an app card (or switch to the **Discovered Paths** tab)
2. The summary cards show counts per classification: Critical, Sensitive, Protected, Public
3. Use the search box to filter by path name
4. Use the classification dropdown to filter by security level
5. **To change a classification**: Use the inline dropdown in the Classification column
   - Select a different level (Critical, Sensitive, Protected, Public)
   - The change is saved immediately and marked as a manual override
   - Manual overrides are preserved when re-running discovery

### Publishing Paths

1. On the Discovered Paths tab, select paths using the checkboxes
2. Click **Publish Selected (N)**
3. In the confirmation dialog:
   - Optionally enable **OpenZiti** for zero-trust overlay networking
   - Optionally enable **BrowZer** for clientless browser access
4. Click **Publish**
5. Published paths appear on the **Published** tab with links to their proxy routes

### Viewing Published Routes

1. Switch to the **Published** tab
2. Each row shows the path, methods, classification, auth policy, and a link to the proxy route
3. Click **View Route** to navigate to the Proxy Routes page for further configuration

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/access/apps` | List registered apps |
| `POST` | `/api/v1/access/apps` | Register a new app |
| `GET` | `/api/v1/access/apps/:id` | Get app details |
| `DELETE` | `/api/v1/access/apps/:id` | Delete an app and its paths |
| `POST` | `/api/v1/access/apps/:id/discover` | Start async discovery |
| `GET` | `/api/v1/access/apps/:id/paths` | List discovered paths |
| `PUT` | `/api/v1/access/apps/:id/paths/:pathId` | Update path classification |
| `POST` | `/api/v1/access/apps/:id/publish` | Publish selected paths as routes |

## Policy Examples

### Critical Path (admin + device trust)
```json
{
  "require_auth": true,
  "allowed_roles": ["admin"],
  "require_device_trust": true
}
```

### Sensitive Path (admin only)
```json
{
  "require_auth": true,
  "allowed_roles": ["admin"]
}
```

### Protected Path (any authenticated user)
```json
{
  "require_auth": true,
  "allowed_roles": []
}
```

### Public Path (no auth)
```json
{
  "require_auth": false,
  "allowed_roles": []
}
```

## Architecture

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐
│ Admin Console │────>│  Access Service  │────>│  Target App      │
│ (app-publish) │     │  /api/v1/access  │     │  (internal)      │
└──────────────┘     │  /apps/*         │     └──────────────────┘
                     │                  │              │
                     │  Discovery Engine│<─────────────┘
                     │  - OpenAPI parse │     HTTP probes
                     │  - Path probing  │
                     │  - Sitemap parse │
                     │  - HTML crawl    │
                     │                  │
                     │  Classification  │
                     │  Engine          │
                     │                  │
                     │  Publish Handler │──────> proxy_routes table
                     │  (creates routes)│──────> Ziti/BrowZer (optional)
                     └─────────────────┘
```
