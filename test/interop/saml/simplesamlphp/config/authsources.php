<?php

declare(strict_types=1);

// The SimpleSAMLphp service provider under test. The per-profile settings
// come from the profile file the interop harness writes before each profile
// (SSP_PROFILE), read on every request.

$profileFile = getenv('SSP_PROFILE') ?: (__DIR__ . '/profile.json');
$profile = is_file($profileFile) ? (json_decode((string) file_get_contents($profileFile), true) ?: []) : [];
$signRequests = (bool) ($profile['sign_authnrequest'] ?? true);

$config = [
    'openidx' => [
        'saml:SP',
        'entityID' => getenv('SSP_ENTITY_ID') ?: 'urn:openidx:interop:simplesamlphp',
        'idp' => getenv('IDP_ENTITY_ID') ?: 'http://localhost:8006',
        'privatekey' => 'sp.key',
        'certificate' => 'sp.crt',
        'NameIDPolicy' => [
            'Format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            'AllowCreate' => true,
        ],
        'signature.algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        // AuthnRequests and logout messages go out signed (HTTP-Redirect)...
        'sign.authnrequest' => $signRequests,
        'redirect.sign' => $signRequests,
        'sign.logout' => true,
        // ...and the IdP's logout messages must be signed too.
        'validate.logout' => true,
        'redirect.validate' => true,
        'WantAssertionsSigned' => true,
        // Refuse a plaintext assertion in the encrypted profile.
        'assertion.encryption' => (bool) ($profile['require_encryption'] ?? false),
    ],
];
