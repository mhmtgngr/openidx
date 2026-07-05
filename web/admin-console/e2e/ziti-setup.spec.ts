import { test, expect } from '@playwright/test';

const mockSetupStatus = {
  ready: false,
  summary: '3 of 6 required steps complete',
  steps: [
    {
      id: 'controller',
      title: 'Connect the Ziti controller',
      description: 'OpenIDX drives one OpenZiti controller.',
      status: 'complete',
      detail: 'Controller reachable at https://ziti-controller:1280',
    },
    {
      id: 'pki',
      title: "Trust the controller's CA",
      description: 'OpenIDX verifies the controller TLS certificate against ca.pem.',
      status: 'warning',
      detail: 'TLS verification is DISABLED (insecure_skip_verify).',
      remediation: 'Copy the controller CA to /ziti/ca.pem and turn verification back on.',
    },
    {
      id: 'routers',
      title: 'Run at least one edge router',
      description: 'Edge routers are the data plane.',
      status: 'action_needed',
      detail: 'No edge routers registered.',
      remediation:
        'On the controller: ziti edge create edge-router edge1 --jwt-output-file edge1.jwt --tunneler-enabled',
      action_label: 'View routers',
      action_href: '/ziti-network?tab=overview',
    },
  ],
  components: [
    {
      id: 'controller',
      name: 'OpenZiti Controller',
      role: 'Control plane: identities, services, policies.',
      required: 'required',
      status: 'complete',
    },
    {
      id: 'edge-router',
      name: 'Ziti Edge Router',
      role: 'Data plane. Every connection transits a router.',
      required: 'required',
      status: 'action_needed',
      detail: '0/0 online',
      install: [
        'Create on the controller: ziti edge create edge-router edge1 --jwt-output-file edge1.jwt --tunneler-enabled',
      ],
    },
    {
      id: 'tunneler',
      name: 'Ziti tunneler / OpenIDX Agent (client devices)',
      role: 'Per-device client for non-browser apps.',
      required: 'optional',
      status: 'optional',
    },
  ],
  routes: [
    {
      route_name: 'internal-wiki',
      service_name: 'openidx-internal-wiki',
      to_url: 'https://wiki.example.com',
      stored_mode: 'identity',
      effective_mode: 'hop',
      browzer_enabled: true,
      route_enabled: true,
      hop_port: 8103,
      next_hop:
        'edge router (host.v1) → hop nginx 127.0.0.1:8103 (SNI demux + Host rewrite) → https://wiki.example.com',
      client_side: 'Nothing to install — browser via BrowZer (dials as #browzer-users)',
      reconcile_state: 'synced',
      requirements: ['≥1 online edge router tagged #ziti-routers'],
      warnings: ["stored mode 'identity' is invalid for BrowZer — auto-corrected to 'hop'"],
    },
  ],
  routers: [],
  sync_status: { unsynced_users: 2, total_users: 10, total_identities: 8 },
};

test.describe('Ziti Network Setup', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/setup/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockSetupStatus),
      });
    });
  });

  test('shows checklist, install advisor and topology', async ({ page }) => {
    await page.goto('/ziti-setup');

    await expect(page.getByRole('heading', { name: 'Network Setup' })).toBeVisible();
    await expect(page.getByText('Network at a glance')).toBeVisible();
    await expect(page.getByText('Setup checklist')).toBeVisible();
    await expect(page.getByText('Connect the Ziti controller')).toBeVisible();
    await expect(page.getByText('What you need to install')).toBeVisible();
    await expect(page.getByText('OpenZiti Controller')).toBeVisible();
    await expect(page.getByText('3 of 6 required steps complete')).toBeVisible();
  });

  test('shows remediation for incomplete steps and expands install commands', async ({ page }) => {
    await page.goto('/ziti-setup');

    await expect(page.getByText('No edge routers registered.')).toBeVisible();
    // Expand the edge-router install instructions.
    await page.getByRole('button', { name: 'How to install' }).first().click();
    await expect(page.getByText(/ziti edge create edge-router edge1/).first()).toBeVisible();
  });

  test('shows per-route advice with effective mode and data path', async ({ page }) => {
    await page.goto('/ziti-setup');

    await expect(page.getByText('Your applications on the network')).toBeVisible();
    await expect(page.getByText('internal-wiki')).toBeVisible();
    // Expand the route row.
    await page.getByText('internal-wiki').click();
    await expect(page.getByText(/hop nginx 127\.0\.0\.1:8103/)).toBeVisible();
    await expect(page.getByText(/auto-corrected/)).toBeVisible();
  });
});
