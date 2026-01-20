UPDATE users SET password_hash = '$2a$10$OMlUsSDc4iIhrl93McN48u2RC.kQ4rY.prG9VrfULxIFRrD.4TnsC' WHERE username = 'admin';
SELECT username, password_hash FROM users WHERE username = 'admin';
