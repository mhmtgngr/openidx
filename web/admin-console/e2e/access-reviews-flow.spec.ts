import { test, expect } from '@playwright/test';
import { AccessReviewsPage } from './pages/access-reviews.page';
import { ReviewDetailPage } from './pages/review-detail.page';

/**
 * Access Reviews E2E Tests
 * Tests for creating, viewing, and completing access reviews
 */

const mockReviews = [
  {
    id: 'review-1',
    name: 'Q1 2026 User Access Review',
    description: 'Quarterly review of all user access rights',
    type: 'user_access',
    status: 'pending',
    reviewer_id: 'admin-1',
    start_date: '2026-01-01T00:00:00Z',
    end_date: '2026-01-31T23:59:59Z',
    created_at: '2025-12-15T00:00:00Z',
    completed_at: null,
    total_items: 25,
    reviewed_items: 0,
  },
  {
    id: 'review-2',
    name: 'Role Assignment Review',
    description: 'Review of all role assignments',
    type: 'role_assignment',
    status: 'in_progress',
    reviewer_id: 'admin-1',
    start_date: '2026-02-01T00:00:00Z',
    end_date: '2026-02-28T23:59:59Z',
    created_at: '2026-01-15T00:00:00Z',
    completed_at: null,
    total_items: 15,
    reviewed_items: 8,
  },
  {
    id: 'review-3',
    name: 'Application Access Review',
    description: 'Review of application-level permissions',
    type: 'application_access',
    status: 'completed',
    reviewer_id: 'admin-1',
    start_date: '2025-12-01T00:00:00Z',
    end_date: '2025-12-31T23:59:59Z',
    created_at: '2025-11-15T00:00:00Z',
    completed_at: '2025-12-28T10:30:00Z',
    total_items: 40,
    reviewed_items: 40,
  },
];

const mockReviewItems = [
  {
    id: 'item-1',
    review_id: 'review-1',
    user_id: 'user-123',
    resource_type: 'role',
    resource_id: 'role-admin',
    resource_name: 'Administrator',
    decision: 'pending',
    decided_by: null,
    decided_at: null,
    comments: '',
  },
  {
    id: 'item-2',
    review_id: 'review-1',
    user_id: 'user-456',
    resource_type: 'application',
    resource_id: 'app-dashboard',
    resource_name: 'Dashboard App',
    decision: 'pending',
    decided_by: null,
    decided_at: null,
    comments: '',
  },
  {
    id: 'item-3',
    review_id: 'review-1',
    user_id: 'user-789',
    resource_type: 'permission',
    resource_id: 'perm-write',
    resource_name: 'Write Permission',
    decision: 'approved',
    decided_by: 'admin-1',
    decided_at: '2026-01-15T10:30:00Z',
    comments: 'Verified access needed',
  },
];

test.describe('Access Reviews List', () => {
  let reviewsPage: AccessReviewsPage;

  test.beforeEach(async ({ page }) => {
    reviewsPage = new AccessReviewsPage(page);

    // Mock authentication
    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

    // Mock reviews API
    await page.route('**/api/v1/governance/reviews*', async (route) => {
      const url = new URL(route.request().url());
      const search = url.searchParams.get('search') || '';
      const status = url.searchParams.get('status') || '';
      const offset = parseInt(url.searchParams.get('offset') || '0', 10);

      let filteredReviews = mockReviews;

      // Apply search filter
      if (search) {
        filteredReviews = mockReviews.filter(r =>
          r.name.toLowerCase().includes(search.toLowerCase()) ||
          (r.description && r.description.toLowerCase().includes(search.toLowerCase()))
        );
      }

      // Apply status filter
      if (status) {
        filteredReviews = filteredReviews.filter(r => r.status === status);
      }

      // Apply pagination
      const paginatedReviews = filteredReviews.slice(offset, offset + 20);

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'x-total-count': String(filteredReviews.length) },
        body: JSON.stringify(paginatedReviews),
      });
    });
  });

  test('should display access reviews list page', async ({ page }) => {
    await reviewsPage.goto();

    await expect(reviewsPage.pageTitle).toBeVisible();
    await expect(reviewsPage.pageDescription).toBeVisible();
    await expect(reviewsPage.createReviewButton).toBeVisible();
  });

  test('should display reviews in table', async ({ page }) => {
    await reviewsPage.goto();

    const reviewCount = await reviewsPage.getReviewCount();
    expect(reviewCount).toBeGreaterThan(0);

    // Check for known review
    await expect(page.locator('text=Q1 2026 User Access Review')).toBeVisible();
  });

  test('should display review status badges', async ({ page }) => {
    await reviewsPage.goto();

    const pendingStatus = await reviewsPage.getReviewStatus('Q1 2026 User Access Review');
    expect(pendingStatus).toContain('pending');

    const completedStatus = await reviewsPage.getReviewStatus('Application Access Review');
    expect(completedStatus).toContain('completed');
  });

  test('should display review progress', async ({ page }) => {
    await reviewsPage.goto();

    const progress = await reviewsPage.getReviewProgress('Role Assignment Review');
    expect(progress).not.toBeNull();
    expect(progress?.reviewed).toBe(8);
    expect(progress?.total).toBe(15);
  });

  test('should filter reviews by search', async ({ page }) => {
    await reviewsPage.goto();

    const initialCount = await reviewsPage.getReviewCount();

    await reviewsPage.search('Role');

    const filteredCount = await reviewsPage.getReviewCount();
    expect(filteredCount).toBeLessThanOrEqual(initialCount);
  });

  test('should filter reviews by status', async ({ page }) => {
    await reviewsPage.goto();

    await reviewsPage.filterByStatus('completed');

    // Should only show completed reviews
    const reviewCount = await reviewsPage.getReviewCount();
    for (let i = 0; i < reviewCount; i++) {
      const row = reviewsPage.reviewRows.nth(i);
      await expect(row.locator('text=completed')).toBeVisible();
    }
  });

  test('should display stats cards', async ({ page }) => {
    await reviewsPage.goto();

    const pendingCount = await reviewsPage.getPendingCount();
    const inProgressCount = await reviewsPage.getInProgressCount();
    const completedCount = await reviewsPage.getCompletedCount();

    expect(pendingCount).toBeGreaterThanOrEqual(0);
    expect(inProgressCount).toBeGreaterThanOrEqual(0);
    expect(completedCount).toBeGreaterThanOrEqual(0);
  });
});

test.describe('Create Access Review', () => {
  let reviewsPage: AccessReviewsPage;

  test.beforeEach(async ({ page }) => {
    reviewsPage = new AccessReviewsPage(page);

    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

    // Mock reviews API for GET requests
    await page.route('**/api/v1/governance/reviews*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'x-total-count': '0' },
          body: JSON.stringify([]),
        });
      } else if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-review-id',
            ...body,
            status: 'pending',
            created_at: new Date().toISOString(),
            completed_at: null,
            total_items: 0,
            reviewed_items: 0,
          }),
        });
      }
    });
  });

  test('should open create review modal', async ({ page }) => {
    await reviewsPage.goto();
    await reviewsPage.openCreateReviewModal();

    await expect(reviewsPage.createReviewDialogTitle).toBeVisible();
  });

  test('should display all form fields', async ({ page }) => {
    await reviewsPage.goto();
    await reviewsPage.openCreateReviewModal();

    await expect(reviewsPage.reviewNameInput).toBeVisible();
    await expect(reviewsPage.reviewDescriptionInput).toBeVisible();
    await expect(reviewsPage.reviewTypeSelect).toBeVisible();
    await expect(reviewsPage.startDateInput).toBeVisible();
    await expect(reviewsPage.endDateInput).toBeVisible();
  });

  test('should create review with valid data', async ({ page }) => {
    await reviewsPage.goto();

    await reviewsPage.createReview({
      name: 'Q2 2026 Review',
      description: 'Quarterly access review for Q2',
      type: 'user_access',
      startDate: '2026-04-01',
      endDate: '2026-04-30',
    });

    // Verify success toast
    await expect(page.locator('text=/created successfully/i')).toBeVisible();
  });

  test('should validate required fields', async ({ page }) => {
    await reviewsPage.goto();
    await reviewsPage.openCreateReviewModal();

    // Try to submit without filling form
    await reviewsPage.submitCreateReview();

    // Modal should still be visible (HTML5 validation)
    await expect(reviewsPage.createReviewDialogTitle).toBeVisible();
  });

  test('should validate date range (end before start)', async ({ page }) => {
    await reviewsPage.goto();
    await reviewsPage.openCreateReviewModal();

    await reviewsPage.fillReviewForm({
      name: 'Invalid Date Review',
      startDate: '2026-06-01',
      endDate: '2026-05-01', // End before start
    });

    await reviewsPage.submitCreateReview();

    // Should show validation error about date range
    await expect(page.locator('text=/end date must be after start date/i')).toBeVisible();
  });

  test('should close modal on cancel', async ({ page }) => {
    await reviewsPage.goto();
    await reviewsPage.openCreateReviewModal();

    await reviewsPage.cancelButton.click();

    await expect(reviewsPage.createReviewDialogTitle).not.toBeVisible();
  });
});

test.describe('Review Detail and Decision Flow', () => {
  let reviewsPage: AccessReviewsPage;
  let reviewDetailPage: ReviewDetailPage;

  test.beforeEach(async ({ page }) => {
    reviewsPage = new AccessReviewsPage(page);
    reviewDetailPage = new ReviewDetailPage(page, 'review-1');

    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

    // Mock review detail API
    await page.route('**/api/v1/governance/reviews/review-1', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockReviews[0]),
      });
    });

    // Mock review items API
    await page.route('**/api/v1/governance/reviews/review-1/items*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockReviewItems),
      });
    });

    // Mock start review API
    await page.route('**/api/v1/governance/reviews/review-1/status', async (route) => {
      if (route.request().method() === 'PATCH') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ...mockReviews[0], status: 'in_progress' }),
        });
      }
    });

    // Mock decision API
    await page.route('**/api/v1/governance/reviews/review-1/items/*/decision', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'Decision recorded' }),
      });
    });

    // Mock batch decision API
    await page.route('**/api/v1/governance/reviews/review-1/items/batch-decision', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'Decisions recorded' }),
      });
    });
  });

  test('should navigate to review detail page', async ({ page }) => {
    await reviewDetailPage.goto();

    await expect(reviewDetailPage.reviewTitle).toBeVisible();
    await expect(reviewDetailPage.reviewTitle).toContainText('Q1 2026 User Access Review');
  });

  test('should display review items table', async ({ page }) => {
    await reviewDetailPage.goto();

    const itemCount = await reviewDetailPage.getItemCount();
    expect(itemCount).toBeGreaterThan(0);
  });

  test('should start a pending review', async ({ page }) => {
    await reviewDetailPage.goto();

    await expect(reviewDetailPage.startReviewButton).toBeVisible();
    await reviewDetailPage.startReview();

    // Verify start button is gone
    await expect(reviewDetailPage.startReviewButton).not.toBeVisible();
  });

  test('should display pending items count', async ({ page }) => {
    await reviewDetailPage.goto();

    const pendingCount = await reviewDetailPage.getPendingItemsCount();
    expect(pendingCount).toBeGreaterThanOrEqual(0);
  });

  test('should display progress', async ({ page }) => {
    await reviewDetailPage.goto();

    const progress = await reviewDetailPage.getProgressPercentage();
    expect(progress).toBeGreaterThanOrEqual(0);
    expect(progress).toBeLessThanOrEqual(100);
  });

  test('should filter items by decision status', async ({ page }) => {
    await reviewDetailPage.goto();

    await reviewDetailPage.filterByDecision('pending');

    // All visible items should be pending
    const itemCount = await reviewDetailPage.getItemCount();
    for (let i = 0; i < itemCount; i++) {
      const decision = await reviewDetailPage.getItemDecision(i);
      expect(decision).toContain('pending');
    }
  });

  test('should quick approve an item', async ({ page }) => {
    // Mock with pending items
    await page.route('**/api/v1/governance/reviews/review-1/items*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            id: 'item-1',
            review_id: 'review-1',
            user_id: 'user-123',
            resource_type: 'role',
            resource_id: 'role-admin',
            resource_name: 'Administrator',
            decision: 'pending',
            decided_by: null,
            decided_at: null,
            comments: '',
          },
        ]),
      });
    });

    await reviewDetailPage.goto();

    await reviewDetailPage.quickApproveItem(0);

    // Verify success toast
    await expect(page.locator('text=/decision recorded/i')).toBeVisible();
  });

  test('should quick revoke an item', async ({ page }) => {
    // Mock with pending items
    await page.route('**/api/v1/governance/reviews/review-1/items*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            id: 'item-1',
            review_id: 'review-1',
            user_id: 'user-123',
            resource_type: 'role',
            resource_id: 'role-admin',
            resource_name: 'Administrator',
            decision: 'pending',
            decided_by: null,
            decided_at: null,
            comments: '',
          },
        ]),
      });
    });

    await reviewDetailPage.goto();

    await reviewDetailPage.quickRevokeItem(0);

    // Verify success toast
    await expect(page.locator('text=/decision recorded/i')).toBeVisible();
  });

  test('should select and approve multiple items', async ({ page }) => {
    // Mock with multiple pending items
    await page.route('**/api/v1/governance/reviews/review-1/items*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            id: 'item-1',
            review_id: 'review-1',
            user_id: 'user-123',
            resource_type: 'role',
            resource_id: 'role-admin',
            resource_name: 'Administrator',
            decision: 'pending',
            decided_by: null,
            decided_at: null,
            comments: '',
          },
          {
            id: 'item-2',
            review_id: 'review-1',
            user_id: 'user-456',
            resource_type: 'application',
            resource_id: 'app-dashboard',
            resource_name: 'Dashboard App',
            decision: 'pending',
            decided_by: null,
            decided_at: null,
            comments: '',
          },
        ]),
      });
    });

    await reviewDetailPage.goto();

    // Select all items
    await reviewDetailPage.selectAllItems();

    // Approve selected
    await reviewDetailPage.approveSelected('Bulk approve for verified users');

    // Verify success
    await expect(page.locator('text=/decisions recorded/i')).toBeVisible();
  });

  test('should add comments when making decision', async ({ page }) => {
    // Mock with pending items
    await page.route('**/api/v1/governance/reviews/review-1/items*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            id: 'item-1',
            review_id: 'review-1',
            user_id: 'user-123',
            resource_type: 'role',
            resource_id: 'role-admin',
            resource_name: 'Administrator',
            decision: 'pending',
            decided_by: null,
            decided_at: null,
            comments: '',
          },
        ]),
      });
    });

    await reviewDetailPage.goto();

    await reviewDetailPage.selectAllItems();

    // Revoke with comment
    await reviewDetailPage.revokeSelected('Access no longer required');

    // Verify decision modal was shown
    await expect(page.locator('text=/decision recorded/i')).toBeVisible();
  });

  test('should navigate back to reviews list', async ({ page }) => {
    await reviewDetailPage.goto();

    await reviewDetailPage.goBack();

    await expect(page).toHaveURL('**/access-reviews');
  });

  test('should complete review when all items are decided', async ({ page }) => {
    // Mock review with no pending items
    await page.route('**/api/v1/governance/reviews/review-1', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          ...mockReviews[0],
          status: 'in_progress',
          total_items: 3,
          reviewed_items: 3,
        }),
      });
    });

    // Mock items all decided
    await page.route('**/api/v1/governance/reviews/review-1/items*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            id: 'item-1',
            review_id: 'review-1',
            user_id: 'user-123',
            resource_type: 'role',
            resource_id: 'role-admin',
            resource_name: 'Administrator',
            decision: 'approved',
            decided_by: 'admin-1',
            decided_at: '2026-01-15T10:30:00Z',
            comments: '',
          },
          {
            id: 'item-2',
            review_id: 'review-1',
            user_id: 'user-456',
            resource_type: 'application',
            resource_id: 'app-dashboard',
            resource_name: 'Dashboard App',
            decision: 'approved',
            decided_by: 'admin-1',
            decided_at: '2026-01-15T10:30:00Z',
            comments: '',
          },
          {
            id: 'item-3',
            review_id: 'review-1',
            user_id: 'user-789',
            resource_type: 'permission',
            resource_id: 'perm-write',
            resource_name: 'Write Permission',
            decision: 'revoked',
            decided_by: 'admin-1',
            decided_at: '2026-01-15T10:30:00Z',
            comments: '',
          },
        ]),
      });
    });

    await reviewDetailPage.goto();

    await expect(reviewDetailPage.completeReviewButton).toBeVisible();
    await reviewDetailPage.completeReview();

    // Verify success
    await expect(page.locator('text=/review completed/i')).toBeVisible();
  });
});

test.describe('Access Reviews Navigation', () => {
  test('should navigate from list to detail and back', async ({ page }) => {
    // Mock authentication
    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

    // Mock reviews API
    await page.route('**/api/v1/governance/reviews*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'x-total-count': '1' },
          body: JSON.stringify([mockReviews[0]]),
        });
      }
    });

    const reviewsPage = new AccessReviewsPage(page);
    await reviewsPage.goto();

    // Navigate to detail
    await reviewsPage.viewReviewDetails('Q1 2026 User Access Review');

    await expect(page).toHaveURL('**/access-reviews/**');

    // Navigate back
    await page.getByRole('button').locator('svg').first().click();

    await expect(page).toHaveURL('**/access-reviews');
    await expect(reviewsPage.pageTitle).toBeVisible();
  });

  test('should navigate from dashboard to reviews', async ({ page }) => {
    // Mock authentication
    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

    // Mock dashboard API
    await page.route('**/api/v1/dashboard', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_users: 42,
          active_users: 38,
          total_applications: 12,
          active_sessions: 15,
          pending_reviews: 3,
          security_alerts: 0,
          recent_activity: [],
          auth_stats: { total_logins: 1250, successful_logins: 1180, failed_logins: 70 },
        }),
      });
    });

    // Mock reviews API
    await page.route('**/api/v1/governance/reviews*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'x-total-count': '0' },
        body: JSON.stringify([]),
      });
    });

    // Go to dashboard first
    await page.goto('/dashboard');

    // Click on Pending Reviews card
    await page.locator('.grid > div').filter({ hasText: 'Pending Reviews' }).click();

    await expect(page).toHaveURL('**/access-reviews');
  });
});
