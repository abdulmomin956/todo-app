<?php
require_once '../config/database.php';
require_once '../includes/header.php';

class Auth {
    private $db;
    private $conn;

    public function __construct() {
        $this->db = new Database();
        $this->conn = $this->db->getConnection();
    }

    // User registration
    public function register($username, $email, $password) {
        // Validate input
        if (empty($username) || empty($email) || empty($password)) {
            return "All fields are required";
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return "Invalid email format";
        }

        if (strlen($password) < 6) {
            return "Password must be at least 6 characters long";
        }

        // Check if user exists
        $query = "SELECT id FROM users WHERE username = :username OR email = :email";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":username", $username);
        $stmt->bindParam(":email", $email);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            return "Username or email already exists";
        }

        // Hash password and create user
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $query = "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":username", $username);
        $stmt->bindParam(":email", $email);
        $stmt->bindParam(":password", $hashed_password);

        if ($stmt->execute()) {
            return true;
        }
        return "Registration failed";
    }

    // User login
   public function login($username, $password) {
        // Input validation
        if (empty($username) || empty($password)) {
            return "Username and password are required";
        }

        $query = "SELECT id, username, password FROM users WHERE username = :username OR email = :username";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":username", $username);
        
        try {
            $stmt->execute();
            
            if ($stmt->rowCount() == 1) {
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                
                // Debug: Check what's happening
                error_log("Login attempt: " . $username);
                error_log("Stored hash: " . $user['password']);
                error_log("Password verify: " . (password_verify($password, $user['password']) ? 'true' : 'false'));
                
                if (password_verify($password, $user['password'])) {
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    return true;
                } else {
                    return "Invalid password";
                }
            } else {
                return "User not found";
            }
        } catch (PDOException $e) {
            error_log("Login error: " . $e->getMessage());
            return "Database error: " . $e->getMessage();
        }
    }

    // User logout
    public function logout() {
        session_destroy();
        header("Location: ../pages/login.php");
        exit();
    }
}

// FIXED: Handle logout action properly
if (isset($_GET['action']) && $_GET['action'] == 'logout') {
    $auth = new Auth();
    $auth->logout();
}

?>