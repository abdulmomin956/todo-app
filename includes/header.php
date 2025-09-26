<?php
session_start();
ob_start();

// Auto-load classes if needed
spl_autoload_register(function ($class_name) {
    include '../classes/' . $class_name . '.php';
});

// Check if user is logged in
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

// Redirect if not logged in
function requireAuth() {
    if (!isLoggedIn()) {
        header("Location: ../pages/login.php");
        exit();
    }
}

// CSRF protection
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}
?>