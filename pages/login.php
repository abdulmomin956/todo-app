<?php
require_once '../includes/header.php';
require_once '../includes/auth.php';

// Redirect if already logged in
if (isLoggedIn()) {
    header("Location: dashboard.php");
    exit();
}

$auth = new Auth();
$error = $success = "";

// FIXED: Proper form handling with error reporting
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    // Basic validation
    $username = trim($_POST['username'] ?? '');
    $password = trim($_POST['password'] ?? '');
    
    if (empty($username) || empty($password)) {
        $error = "Please enter both username and password";
    } else {
        // Enable error reporting for debugging
        error_reporting(E_ALL);
        ini_set('display_errors', 1);
        
        $result = $auth->login($username, $password);
        
        if ($result === true) {
            // Login successful - redirect to dashboard
            header("Location: dashboard.php");
            exit();
        } else {
            $error = $result;
            // Debug output
            error_log("Login failed: " . $error);
        }
    }
}

// Show success message after registration
if (isset($_GET['registered']) && $_GET['registered'] == 1) {
    $success = "Registration successful! Please login with your credentials.";
}

// Debug: Check session status
error_log("Session status: " . session_status());
error_log("User logged in: " . (isLoggedIn() ? 'yes' : 'no'));
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Task Manager</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .login-container {
            max-width: 400px;
            margin: 100px auto;
            padding: 20px;
        }
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        .card-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 15px 15px 0 0 !important;
            border: none;
            padding: 30px 20px;
        }
        .btn-login {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            padding: 12px;
            font-weight: 600;
        }
        .form-control:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-container">
            <div class="card">
                <div class="card-header text-center">
                    <h2 class="mb-0">Welcome Back</h2>
                    <p class="mb-0 opacity-75">Sign in to your Task Manager</p>
                </div>
                <div class="card-body">
                    <!-- FIXED: Better error/success display -->
                    <?php if ($success): ?>
                        <div class="alert alert-success alert-dismissible fade show" role="alert">
                            <strong>Success!</strong> <?php echo htmlspecialchars($success); ?>
                            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                        </div>
                    <?php endif; ?>
                    
                    <?php if ($error): ?>
                        <div class="alert alert-danger alert-dismissible fade show" role="alert">
                            <strong>Error!</strong> <?php echo htmlspecialchars($error); ?>
                            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                        </div>
                    <?php endif; ?>

                    <!-- FIXED: Form method and action -->
                    <form method="POST" action="" id="loginForm">
                        <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                        
                        <div class="mb-4">
                            <label for="username" class="form-label fw-semibold">Username or Email</label>
                            <input type="text" class="form-control" id="username" name="username" 
                                   value="<?php echo htmlspecialchars($username ?? ''); ?>" 
                                   placeholder="Enter your username or email" required autofocus>
                        </div>
                        
                        <div class="mb-4">
                            <label for="password" class="form-label fw-semibold">Password</label>
                            <div class="input-group">
                                <input type="password" class="form-control" id="password" name="password" 
                                       placeholder="Enter your password" required>
                                <button type="button" class="btn btn-outline-secondary" id="togglePassword">
                                    Show
                                </button>
                            </div>
                        </div>
                        
                        <button type="submit" name="login" class="btn btn-login btn-primary w-100 mb-3">
                            Sign In
                        </button>
                    </form>
                    
                    <hr class="my-4">
                    
                    <div class="text-center">
                        <p class="mb-0">Don't have an account? 
                            <a href="register.php" class="text-decoration-none fw-semibold">Create one here</a>
                        </p>
                    </div>

                    <!-- Debug info (remove in production) -->
                    <div class="mt-3 small text-muted">
                        <div>Session ID: <?php echo session_id(); ?></div>
                        <div>User ID in session: <?php echo $_SESSION['user_id'] ?? 'Not set'; ?></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Toggle password visibility
        document.getElementById('togglePassword').addEventListener('click', function() {
            const passwordInput = document.getElementById('password');
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            this.textContent = type === 'password' ? 'Show' : 'Hide';
        });

        // Simple form validation
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            const username = document.getElementById('username').value.trim();
            const password = document.getElementById('password').value.trim();
            
            if (!username || !password) {
                e.preventDefault();
                alert('Please fill in all required fields');
                return false;
            }
        });
    </script>
</body>
</html>