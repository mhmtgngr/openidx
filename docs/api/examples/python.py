"""
OpenIDX API Examples - Python

This module provides Python client examples for interacting with the OpenIDX API.
"""

import requests
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import urllib.parse


# ============================================
# Authentication
# ============================================

@dataclass
class TokenResponse:
    """OAuth 2.0 Token Response"""
    access_token: str
    refresh_token: Optional[str] = None
    expires_in: int = 3600
    token_type: str = "Bearer"
    scope: Optional[str] = None

    @property
    def expires_at(self) -> datetime:
        """Calculate token expiration time"""
        return datetime.now() + timedelta(seconds=self.expires_in)


class OpenIDXOAuthClient:
    """OAuth 2.0 Client for OpenIDX"""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        token_url: str = "http://localhost:8006/oauth/token",
        scope: str = "openid profile email"
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        self.scope = scope
        self._token_response: Optional[TokenResponse] = None

    def get_client_credentials_token(self) -> str:
        """Get access token using client credentials grant"""
        response = requests.post(
            self.token_url,
            json={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": self.scope
            }
        )
        response.raise_for_status()
        data = response.json()
        self._token_response = TokenResponse(**data)
        return self._token_response.access_token

    def get_password_grant_token(self, username: str, password: str) -> str:
        """Get access token using resource owner password grant"""
        response = requests.post(
            self.token_url,
            json={
                "grant_type": "password",
                "username": username,
                "password": password,
                "scope": self.scope
            }
        )
        response.raise_for_status()
        data = response.json()
        self._token_response = TokenResponse(**data)
        return self._token_response.access_token

    def refresh_access_token(self) -> str:
        """Refresh access token using refresh token"""
        if not self._token_response or not self._token_response.refresh_token:
            raise ValueError("No refresh token available")

        response = requests.post(
            self.token_url,
            json={
                "grant_type": "refresh_token",
                "refresh_token": self._token_response.refresh_token,
                "client_id": self.client_id,
                "client_secret": self.client_secret
            }
        )
        response.raise_for_status()
        data = response.json()
        self._token_response = TokenResponse(**data)
        return self._token_response.access_token

    def get_valid_token(self) -> str:
        """Get valid access token, refreshing if necessary"""
        if (
            not self._token_response
            or datetime.now() >= self._token_response.expires_at - timedelta(seconds=60)
        ):
            if self._token_response and self._token_response.refresh_token:
                return self.refresh_access_token()
            return self.get_client_credentials_token()
        return self._token_response.access_token


# ============================================
# Base API Client
# ============================================

class OpenIDXClient:
    """Base API Client for OpenIDX services"""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str,
        token_url: str = "http://localhost:8006/oauth/token"
    ):
        self.oauth = OpenIDXOAuthClient(client_id, client_secret, token_url)
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()

    def _request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Make authenticated API request"""
        token = self.oauth.get_valid_token()

        headers = kwargs.pop('headers', {})
        headers.update({
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        })

        url = f"{self.base_url}{path}"

        response = self.session.request(
            method=method,
            url=url,
            json=data,
            params=params,
            headers=headers,
            **kwargs
        )

        response.raise_for_status()
        return response.json()

    def get(self, path: str, params: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        """Send GET request"""
        return self._request('GET', path, params=params, **kwargs)

    def post(self, path: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        """Send POST request"""
        return self._request('POST', path, data=data, **kwargs)

    def put(self, path: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        """Send PUT request"""
        return self._request('PUT', path, data=data, **kwargs)

    def delete(self, path: str, **kwargs) -> Dict[str, Any]:
        """Send DELETE request"""
        return self._request('DELETE', path, **kwargs)

    def patch(self, path: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        """Send PATCH request"""
        return self._request('PATCH', path, data=data, **kwargs)


# ============================================
# Identity Service
# ============================================

class IdentityService(OpenIDXClient):
    """Client for Identity Service API"""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str = "http://localhost:8001",
        token_url: str = "http://localhost:8006/oauth/token"
    ):
        super().__init__(client_id, client_secret, base_url, token_url)

    def list_users(
        self,
        offset: int = 0,
        limit: int = 20,
        **params
    ) -> Dict[str, Any]:
        """List users with pagination"""
        all_params = {'offset': offset, 'limit': limit, **params}
        return self.get('/api/v1/identity/users', params=all_params)

    def get_user(self, user_id: str) -> Dict[str, Any]:
        """Get user by ID"""
        return self.get(f'/api/v1/identity/users/{user_id}')

    def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new user"""
        return self.post('/api/v1/identity/users', user_data)

    def update_user(self, user_id: str, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update user"""
        return self.put(f'/api/v1/identity/users/{user_id}', user_data)

    def delete_user(self, user_id: str) -> Dict[str, Any]:
        """Delete user"""
        return self.delete(f'/api/v1/identity/users/{user_id}')

    def get_user_sessions(self, user_id: str) -> Dict[str, Any]:
        """Get user sessions"""
        return self.get(f'/api/v1/identity/users/{user_id}/sessions')

    def create_group(self, group_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create group"""
        return self.post('/api/v1/identity/groups', group_data)

    def list_groups(self, **params) -> Dict[str, Any]:
        """List groups"""
        return self.get('/api/v1/identity/groups', params=params)


# ============================================
# Governance Service
# ============================================

class GovernanceService(OpenIDXClient):
    """Client for Governance Service API"""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str = "http://localhost:8002",
        token_url: str = "http://localhost:8006/oauth/token"
    ):
        super().__init__(client_id, client_secret, base_url, token_url)

    def list_reviews(self, **params) -> Dict[str, Any]:
        """List access reviews"""
        return self.get('/api/v1/governance/reviews', params=params)

    def create_review(self, review_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create access review"""
        return self.post('/api/v1/governance/reviews', review_data)

    def submit_decision(
        self,
        review_id: str,
        item_id: str,
        decision_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Submit review decision"""
        return self.post(
            f'/api/v1/governance/reviews/{review_id}/items/{item_id}/decision',
            decision_data
        )


# ============================================
# Provisioning Service (SCIM)
# ============================================

class ProvisioningService(OpenIDXClient):
    """Client for Provisioning Service (SCIM 2.0) API"""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str = "http://localhost:8003",
        token_url: str = "http://localhost:8006/oauth/token"
    ):
        super().__init__(client_id, client_secret, base_url, token_url)

    def list_scim_users(
        self,
        count: int = 100,
        start_index: int = 1,
        **params
    ) -> Dict[str, Any]:
        """List SCIM users"""
        all_params = {'count': count, 'startIndex': start_index, **params}
        return self.get('/scim/v2/Users', params=all_params)

    def create_scim_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create SCIM user"""
        data = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            **user_data
        }
        return self.post('/scim/v2/Users', data)

    def patch_scim_user(
        self,
        user_id: str,
        operations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Patch SCIM user"""
        data = {
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations': operations
        }
        return self.patch(f'/scim/v2/Users/{user_id}', data)

    def delete_scim_user(self, user_id: str) -> Dict[str, Any]:
        """Delete SCIM user"""
        return self.delete(f'/scim/v2/Users/{user_id}')


# ============================================
# Audit Service
# ============================================

class AuditService(OpenIDXClient):
    """Client for Audit Service API"""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str = "http://localhost:8004",
        token_url: str = "http://localhost:8006/oauth/token"
    ):
        super().__init__(client_id, client_secret, base_url, token_url)

    def query_events(self, **params) -> Dict[str, Any]:
        """Query audit events"""
        return self.get('/api/v1/audit/events', params=params)

    def generate_report(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance report"""
        return self.post('/api/v1/audit/reports', report_data)

    def get_statistics(self, **params) -> Dict[str, Any]:
        """Get audit statistics"""
        return self.get('/api/v1/audit/statistics', params=params)


# ============================================
# Admin API
# ============================================

class AdminAPIService(OpenIDXClient):
    """Client for Admin API"""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str = "http://localhost:8005",
        token_url: str = "http://localhost:8006/oauth/token"
    ):
        super().__init__(client_id, client_secret, base_url, token_url)

    def get_dashboard(self) -> Dict[str, Any]:
        """Get dashboard statistics"""
        return self.get('/api/v1/dashboard')

    def create_application(self, app_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create application"""
        return self.post('/api/v1/applications', app_data)

    def update_settings(self, settings: Dict[str, Any]) -> Dict[str, Any]:
        """Update system settings"""
        return self.put('/api/v1/settings', settings)


# ============================================
# Usage Examples
# ============================================

def example_list_users():
    """Example: List users"""
    identity = IdentityService(
        client_id='your_client_id',
        client_secret='your_client_secret'
    )

    try:
        response = identity.list_users(limit=10)
        print(f"Users: {len(response['data'])} found")
        print(f"Total: {response['meta']['total']}")
        for user in response['data']:
            print(f"  - {user['email']}")
    except requests.HTTPError as e:
        print(f"Error: {e.response.json()}")


def example_create_user():
    """Example: Create a new user"""
    identity = IdentityService(
        client_id='your_client_id',
        client_secret='your_client_secret'
    )

    try:
        new_user = identity.create_user({
            'email': 'newuser@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'password': 'SecurePassword123!',
            'role_id': 'role-id-here'
        })
        print(f"Created user: {new_user['id']}")
    except requests.HTTPError as e:
        print(f"Error: {e.response.json()}")


def example_scim_provisioning():
    """Example: SCIM user provisioning"""
    provisioning = ProvisioningService(
        client_id='your_client_id',
        client_secret='your_client_secret'
    )

    try:
        # Create SCIM user
        new_user = provisioning.create_scim_user({
            'userName': 'scim.user@example.com',
            'name': {
                'givenName': 'SCIM',
                'familyName': 'User'
            },
            'emails': [{
                'primary': True,
                'value': 'scim.user@example.com',
                'type': 'work'
            }],
            'active': True
        })
        print(f"Created SCIM user: {new_user['id']}")
    except requests.HTTPError as e:
        print(f"Error: {e.response.json()}")


def example_access_review():
    """Example: Create and manage access review"""
    governance = GovernanceService(
        client_id='your_client_id',
        client_secret='your_client_secret'
    )

    try:
        # Create review
        review = governance.create_review({
            'name': 'Q1 2024 Access Review',
            'description': 'Quarterly access certification',
            'start_date': '2024-01-01T00:00:00Z',
            'end_date': '2024-01-31T23:59:59Z',
            'reviewer_ids': ['reviewer-user-id'],
            'scope': {
                'type': 'group',
                'group_id': 'group-id'
            }
        })
        print(f"Created review: {review['id']}")
    except requests.HTTPError as e:
        print(f"Error: {e.response.json()}")


def example_audit_query():
    """Example: Query audit events"""
    audit = AuditService(
        client_id='your_client_id',
        client_secret='your_client_secret'
    )

    try:
        events = audit.query_events(
            limit=50,
            sort='timestamp:desc'
        )
        print(f"Found {len(events['data'])} events")
    except requests.HTTPError as e:
        print(f"Error: {e.response.json()}")


# Async version using httpx
try:
    import httpx

    class AsyncOpenIDXClient:
        """Async API Client for OpenIDX services using httpx"""

        def __init__(
            self,
            client_id: str,
            client_secret: str,
            base_url: str,
            token_url: str = "http://localhost:8006/oauth/token"
        ):
            self.client_id = client_id
            self.client_secret = client_secret
            self.base_url = base_url.rstrip('/')
            self.token_url = token_url
            self._access_token: Optional[str] = None
            self._token_expires: Optional[datetime] = None

        async def _get_token(self) -> str:
            """Get access token"""
            if (
                self._access_token
                and self._token_expires
                and datetime.now() < self._token_expires - timedelta(seconds=60)
            ):
                return self._access_token

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.token_url,
                    json={
                        "grant_type": "client_credentials",
                        "client_id": self.client_id,
                        "client_secret": self.client_secret
                    }
                )
                response.raise_for_status()
                data = response.json()
                self._access_token = data['access_token']
                self._token_expires = datetime.now() + timedelta(seconds=data['expires_in'])
                return self._access_token

        async def request(
            self,
            method: str,
            path: str,
            data: Optional[Dict[str, Any]] = None
        ) -> Dict[str, Any]:
            """Make authenticated request"""
            token = await self._get_token()

            async with httpx.AsyncClient() as client:
                response = await client.request(
                    method=method,
                    url=f"{self.base_url}{path}",
                    json=data,
                    headers={
                        'Authorization': f'Bearer {token}',
                        'Content-Type': 'application/json'
                    }
                )
                response.raise_for_status()
                return response.json()

        async def get(self, path: str) -> Dict[str, Any]:
            """Send GET request"""
            return await self.request('GET', path)

        async def post(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
            """Send POST request"""
            return await self.request('POST', path, data)

except ImportError:
    pass


if __name__ == '__main__':
    # Run examples
    print("OpenIDX Python API Examples")
    print("=" * 40)
    example_list_users()
