<?php

declare(strict_types=1);

// SimpleSAMLphp configuration for the OpenIDX SAML interop suite
// (test/interop/saml, .github/workflows/saml-interop.yml). Everything that
// differs between a CI run and a local one comes from the environment.
//
// The session store is SQL (SQLite), not the default PHP session: it is what
// lets SimpleSAMLphp refuse a replayed assertion from another browser, and
// what lets it end a session when the IdP's LogoutRequest arrives over the
// back channel, without the user's cookie.

$env = static function (string $name, string $default): string {
    $value = getenv($name);
    return ($value === false || $value === '') ? $default : $value;
};

$baseURL = rtrim($env('SSP_BASEURL', 'http://localhost:8081'), '/') . '/';
$dataDir = $env('SSP_DATA_DIR', '/tmp/simplesamlphp');

$config = [
    'baseurlpath' => $baseURL,
    'application' => ['baseURL' => $baseURL],
    'certdir' => rtrim($env('SSP_CERT_DIR', __DIR__ . '/../cert'), '/') . '/',
    'loggingdir' => $dataDir,
    'datadir' => $dataDir,
    'tempdir' => $dataDir,
    'cachedir' => $dataDir . '/cache',
    'secretsalt' => 'openidx-interop-not-a-secret',
    'auth.adminpassword' => 'openidx-interop-not-a-secret',
    'admin.checkforupdates' => false,
    'technicalcontact_name' => 'OpenIDX interop',
    'technicalcontact_email' => 'interop@example.test',
    'timezone' => 'UTC',
    'trusted.url.domains' => [parse_url($baseURL, PHP_URL_HOST) . ':' . parse_url($baseURL, PHP_URL_PORT)],
    'production' => false,
    'showerrors' => true,
    'errorreporting' => false,
    'logging.level' => SimpleSAML\Logger::DEBUG,
    'logging.handler' => 'file',
    'logging.logfile' => 'simplesamlphp.log',
    'module.enable' => ['core' => true, 'admin' => false, 'saml' => true],
    // Plain http on localhost in CI; nothing here is a real credential.
    'session.cookie.secure' => false,
    'session.cookie.samesite' => null,
    'language.cookie.secure' => false,
    'store.type' => 'sql',
    'store.sql.dsn' => 'sqlite:' . $dataDir . '/store.sqlite',
    // The IdP's metadata, as the IdP publishes it.
    'metadata.sources' => [
        ['type' => 'xml', 'url' => $env('IDP_METADATA_URL', 'http://localhost:8006/saml/idp/metadata')],
    ],
];
