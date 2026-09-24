<?php

declare(strict_types=1);

// SAML2Int enforcement: with response.require_signed the service provider
// refuses a Response that is not itself signed, even when its assertion is
// ([SDP-IDP30]). The interop profiles set it, so an accepted sign-on proves
// the Response signature verified, not only the assertion's.

$profileFile = getenv('SSP_PROFILE') ?: (__DIR__ . '/profile.json');
$profile = is_file($profileFile) ? (json_decode((string) file_get_contents($profileFile), true) ?: []) : [];

return [
    'response.require_signed' => (bool) ($profile['require_signed_response'] ?? true),
];
