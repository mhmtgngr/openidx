# OpenIDX API Documentation

This is the interactive API documentation for the OpenIDX Zero Trust Access Platform. Built with [Redoc](https://github.com/Redocly/redoc), it provides a beautiful, responsive interface for exploring all OpenIDX API endpoints.

## Viewing the Documentation

### Online (GitHub Pages)

The published documentation is available at: `https://openidx.github.io/openidx/api/`

### Local Development

1. **Start a local server**:
   ```bash
   cd docs/api
   ./serve.sh
   ```
   This starts an HTTP server on port 8080 by default.

2. **Or use Python directly**:
   ```bash
   cd docs/api
   python3 -m http.server 8080
   ```

3. **Open in your browser**:
   ```
   http://localhost:8080
   ```

### Using Docker

```bash
docker run --rm -p 8080:80 -v $(pwd)/docs/api:/usr/share/nginx/html:ro nginx:alpine
```

## Directory Structure

```
docs/api/
├── index.html          # Main documentation page with Redoc
├── config.json         # API service configuration
├── serve.sh            # Local development server
├── examples/           # Code examples by language
│   ├── README.md
│   ├── curl.sh         # Shell/cURL examples
│   ├── javascript.ts   # JavaScript/TypeScript examples
│   ├── python.py       # Python examples
│   └── go.go           # Go examples
└── README.md           # This file
```

## API Services

The documentation covers all OpenIDX services:

| Service | Description | Base URL |
|---------|-------------|----------|
| **Identity Service** | User, group, role, MFA, and identity provider management | `/api/v1/identity` |
| **OAuth/OIDC Service** | OAuth 2.0 authorization server with OpenID Connect | `/oauth` |
| **Governance Service** | Access reviews, certification campaigns, and policy management | `/api/v1/governance` |
| **Provisioning Service** | SCIM 2.0 user and group provisioning | `/scim/v2` |
| **Audit Service** | Audit event logging, compliance reporting, and export | `/api/v1/audit` |
| **Admin API** | Dashboard, system settings, application management | `/api/v1` |
| **Access Service** | Zero Trust access proxy with route management | `/api/v1/access` |
| **Portal Service** | Self-service portal for application access | `/api/v1/portal` |
| **Notifications Service** | User notification management and preferences | `/api/v1/notifications` |
| **Organization Service** | Organization and member management | `/api/v1/organization` |

## Authentication

Most API endpoints require Bearer token authentication using JWT tokens issued by the OAuth Service:

```
Authorization: Bearer <your-jwt-token>
```

See the [Authentication Examples](#) section in the documentation for detailed code samples.

## OpenAPI Specifications

The raw OpenAPI 3.0 specifications are available in the parent directory:
- `../../api/openapi/` - Individual service specifications

### Individual Spec Files

- `identity-service.yaml` - Identity Service
- `oauth-service.yaml` - OAuth/OIDC Service
- `governance-service.yaml` - Governance Service
- `provisioning-service.yaml` - Provisioning Service (SCIM)
- `audit-service.yaml` - Audit Service
- `admin-api.yaml` - Admin API
- `access-service.yaml` - Access Service
- `portal-service.yaml` - Portal Service
- `notifications-service.yaml` - Notifications Service
- `organization-service.yaml` - Organization Service

## Code Examples

The `examples/` directory contains ready-to-use code samples:

- **cURL**: Shell script examples for quick testing
- **JavaScript/TypeScript**: Full client library for browser and Node.js
- **Python**: Synchronous and asynchronous clients
- **Go**: Type-safe client with context support

## Customization

### Styling

The documentation uses custom OpenIDX branding. Colors and styles are defined in `<style>` tags within `index.html`.

### Theme Variables

```css
--openidx-primary: #4f46e5;
--openidx-primary-dark: #4338ca;
--openidx-secondary: #0f172a;
--openidx-accent: #06b6d4;
```

### Redoc Configuration

Redoc is initialized with these options:
- `expandResponses: '200,201'` - Automatically expand successful responses
- `expandSingleSchemaField: true` - Expand single-field schemas
- `scrollYOffset: 140` - Offset for fixed header

## Deployment

### GitHub Pages

The documentation is automatically deployed to GitHub Pages via `.github/workflows/docs.yml` on pushes to the `main` branch.

### Manual Deployment

1. Build the site (no build step needed - it's static HTML)
2. Upload to any static hosting service:
   - GitHub Pages
   - Netlify
   - Vercel
   - AWS S3 + CloudFront

### Custom Domain

To use a custom domain:
1. Add a `CNAME` file at `docs/api/CNAME` with your domain
2. Configure DNS to point to your hosting provider

## API Response Format

All API responses follow a standard format:

### Success Response
```json
{
  "data": { ... },
  "meta": {
    "total": 100,
    "page": 1,
    "per_page": 20
  }
}
```

### Error Response
```json
{
  "error": "error_code",
  "message": "Human-readable error message",
  "status": 400,
  "details": { ... }
}
```

## Support

For questions or issues with the API documentation:
- Open an issue on [GitHub](https://github.com/openidx/openidx/issues)
- See the main [OpenIDX Documentation](../)

## License

Apache License 2.0 - See [LICENSE](../../../LICENSE) for details.
