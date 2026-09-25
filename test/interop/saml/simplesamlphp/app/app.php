<?php

declare(strict_types=1);

// The application behind the SimpleSAMLphp service provider. It does what a
// real one does -- asks the SP for a session and reads what the IdP asserted
// -- and reports it as JSON for the harness:
//
//   /app/login   requireAuth(), then the session
//   /app/whoami  the session, or its absence; never redirects
//   /app/logout  SP-initiated Single Logout, then back to /app/whoami

require_once (getenv('SSP_DIR') ?: '/var/simplesamlphp') . '/public/_include.php';

$as = new \SimpleSAML\Auth\Simple('openidx');
$path = (string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$self = rtrim((string) (getenv('SSP_BASEURL') ?: 'http://localhost:8081'), '/');

$report = static function () use ($as): void {
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    if (!$as->isAuthenticated()) {
        echo json_encode(['authenticated' => false]);
        return;
    }
    $nameId = $as->getAuthData('saml:sp:NameID');
    echo json_encode([
        'authenticated' => true,
        'attributes' => $as->getAttributes(),
        'nameId' => $nameId instanceof \SAML2\XML\saml\NameID ? $nameId->getValue() : null,
        'sessionIndex' => $as->getAuthData('saml:sp:SessionIndex'),
    ], JSON_UNESCAPED_SLASHES);
};

switch ($path) {
    case '/app/login':
        $as->requireAuth(['ReturnTo' => $self . '/app/whoami']);
        $report();
        break;
    case '/app/whoami':
        $report();
        break;
    case '/app/logout':
        $as->logout(['ReturnTo' => $self . '/app/whoami']);
        break;
    default:
        http_response_code(404);
        echo 'not found';
}
