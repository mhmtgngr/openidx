<?php

declare(strict_types=1);

// Router for PHP's built-in web server: /app/* is the test application,
// everything else is SimpleSAMLphp's own public directory.
$path = (string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (str_starts_with($path, '/app/')) {
    require __DIR__ . '/app.php';
    return true;
}
return false;
