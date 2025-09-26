<?php
/**
 * Validation and Security Functions
 * Provides input validation, sanitization, and security utilities
 */

class Validation {
    
    /**
     * Sanitize input data
     */
    public static function sanitizeInput($data) {
        if (is_array($data)) {
            return array_map([self::class, 'sanitizeInput'], $data);
        }
        
        $data = trim($data);
        $data = stripslashes($data);
        $data = htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        
        return $data;
    }
    
    /**
     * Validate username
     */
    public static function validateUsername($username) {
        $username = self::sanitizeInput($username);
        
        if (empty($username)) {
            return ['valid' => false, 'message' => 'Username is required'];
        }
        
        if (strlen($username) < 3) {
            return ['valid' => false, 'message' => 'Username must be at least 3 characters long'];
        }
        
        if (strlen($username) > 50) {
            return ['valid' => false, 'message' => 'Username cannot exceed 50 characters'];
        }
        
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            return ['valid' => false, 'message' => 'Username can only contain letters, numbers, and underscores'];
        }
        
        return ['valid' => true, 'data' => $username];
    }
    
    /**
     * Validate email
     */
    public static function validateEmail($email) {
        $email = self::sanitizeInput($email);
        
        if (empty($email)) {
            return ['valid' => false, 'message' => 'Email is required'];
        }
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['valid' => false, 'message' => 'Invalid email format'];
        }
        
        if (strlen($email) > 100) {
            return ['valid' => false, 'message' => 'Email cannot exceed 100 characters'];
        }
        
        return ['valid' => true, 'data' => $email];
    }
    
    /**
     * Validate password
     */
    public static function validatePassword($password, $confirm_password = null) {
        if (empty($password)) {
            return ['valid' => false, 'message' => 'Password is required'];
        }
        
        if (strlen($password) < 6) {
            return ['valid' => false, 'message' => 'Password must be at least 6 characters long'];
        }
        
        if (strlen($password) > 255) {
            return ['valid' => false, 'message' => 'Password cannot exceed 255 characters'];
        }
        
        // Check password strength (optional)
        if (!preg_match('/[A-Z]/', $password)) {
            return ['valid' => false, 'message' => 'Password should contain at least one uppercase letter'];
        }
        
        if (!preg_match('/[a-z]/', $password)) {
            return ['valid' => false, 'message' => 'Password should contain at least one lowercase letter'];
        }
        
        if (!preg_match('/[0-9]/', $password)) {
            return ['valid' => false, 'message' => 'Password should contain at least one number'];
        }
        
        // Confirm password match (for registration)
        if ($confirm_password !== null && $password !== $confirm_password) {
            return ['valid' => false, 'message' => 'Passwords do not match'];
        }
        
        return ['valid' => true, 'data' => $password];
    }
    
    /**
     * Validate task title
     */
    public static function validateTaskTitle($title) {
        $title = self::sanitizeInput($title);
        
        if (empty($title)) {
            return ['valid' => false, 'message' => 'Task title is required'];
        }
        
        if (strlen($title) < 1) {
            return ['valid' => false, 'message' => 'Task title cannot be empty'];
        }
        
        if (strlen($title) > 255) {
            return ['valid' => false, 'message' => 'Task title cannot exceed 255 characters'];
        }
        
        return ['valid' => true, 'data' => $title];
    }
    
    /**
     * Validate task description
     */
    public static function validateTaskDescription($description) {
        $description = self::sanitizeInput($description);
        
        if (strlen($description) > 1000) {
            return ['valid' => false, 'message' => 'Task description cannot exceed 1000 characters'];
        }
        
        return ['valid' => true, 'data' => $description];
    }
    
    /**
     * Validate task ID
     */
    public static function validateTaskId($task_id) {
        if (!is_numeric($task_id) || $task_id <= 0) {
            return ['valid' => false, 'message' => 'Invalid task ID'];
        }
        
        if (!filter_var($task_id, FILTER_VALIDATE_INT)) {
            return ['valid' => false, 'message' => 'Invalid task ID format'];
        }
        
        return ['valid' => true, 'data' => (int)$task_id];
    }
    
    /**
     * Validate task status
     */
    public static function validateTaskStatus($status) {
        $allowed_statuses = ['pending', 'completed'];
        
        if (!in_array($status, $allowed_statuses)) {
            return ['valid' => false, 'message' => 'Invalid task status'];
        }
        
        return ['valid' => true, 'data' => $status];
    }
    
    /**
     * Validate CSRF token
     */
    public static function validateCSRFToken($token) {
        if (empty($token)) {
            return ['valid' => false, 'message' => 'CSRF token is required'];
        }
        
        if (!isset($_SESSION['csrf_token'])) {
            return ['valid' => false, 'message' => 'CSRF token not found in session'];
        }
        
        if (!hash_equals($_SESSION['csrf_token'], $token)) {
            return ['valid' => false, 'message' => 'Invalid CSRF token'];
        }
        
        return ['valid' => true];
    }
    
    /**
     * Validate integer ID
     */
    public static function validateId($id, $fieldName = 'ID') {
        if (!is_numeric($id) || $id <= 0) {
            return ['valid' => false, 'message' => "Invalid $fieldName"];
        }
        
        if (!filter_var($id, FILTER_VALIDATE_INT)) {
            return ['valid' => false, 'message' => "Invalid $fieldName format"];
        }
        
        return ['valid' => true, 'data' => (int)$id];
    }
    
    /**
     * Validate text length
     */
    public static function validateTextLength($text, $fieldName, $minLength = 1, $maxLength = 255) {
        $text = self::sanitizeInput($text);
        $length = strlen($text);
        
        if ($length < $minLength) {
            return ['valid' => false, 'message' => "$fieldName must be at least $minLength characters long"];
        }
        
        if ($length > $maxLength) {
            return ['valid' => false, 'message' => "$fieldName cannot exceed $maxLength characters"];
        }
        
        return ['valid' => true, 'data' => $text];
    }
    
    /**
     * Validate date format
     */
    public static function validateDate($date, $format = 'Y-m-d H:i:s') {
        $d = DateTime::createFromFormat($format, $date);
        if ($d && $d->format($format) === $date) {
            return ['valid' => true, 'data' => $date];
        }
        
        return ['valid' => false, 'message' => 'Invalid date format'];
    }
    
    /**
     * Check if string contains XSS attempts
     */
    public static function detectXSS($string) {
        $xss_patterns = [
            '/<script\b[^>]*>(.*?)<\/script>/is',
            '/on\w+\s*=\s*"[^"]*"/i',
            '/on\w+\s*=\s*\'[^\']*\'/i',
            '/javascript:\s*[^"]*/i',
            '/vbscript:\s*[^"]*/i',
            '/expression\s*\([^)]*\)/i'
        ];
        
        foreach ($xss_patterns as $pattern) {
            if (preg_match($pattern, $string)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Prevent XSS attacks
     */
    public static function preventXSS($data) {
        if (is_array($data)) {
            return array_map([self::class, 'preventXSS'], $data);
        }
        
        // Remove JavaScript event attributes
        $data = preg_replace('/on\w+\s*=\s*"[^"]*"/i', '', $data);
        $data = preg_replace('/on\w+\s*=\s*\'[^\']*\'/i', '', $data);
        
        // Remove script tags
        $data = preg_replace('/<script\b[^>]*>(.*?)<\/script>/is', '', $data);
        
        // Remove dangerous protocols
        $data = preg_replace('/javascript:\s*[^"]*/i', '', $data);
        $data = preg_replace('/vbscript:\s*[^"]*/i', '', $data);
        
        return self::sanitizeInput($data);
    }
    
    /**
     * Validate file upload
     */
    public static function validateFileUpload($file, $allowed_types = [], $max_size = 2097152) { // 2MB default
        $errors = [];
        
        // Check for upload errors
        if ($file['error'] !== UPLOAD_ERR_OK) {
            $upload_errors = [
                UPLOAD_ERR_INI_SIZE => 'File exceeds upload_max_filesize directive in php.ini',
                UPLOAD_ERR_FORM_SIZE => 'File exceeds MAX_FILE_SIZE directive in HTML form',
                UPLOAD_ERR_PARTIAL => 'File was only partially uploaded',
                UPLOAD_ERR_NO_FILE => 'No file was uploaded',
                UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',
                UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',
                UPLOAD_ERR_EXTENSION => 'File upload stopped by extension'
            ];
            
            return ['valid' => false, 'message' => $upload_errors[$file['error']] ?? 'Unknown upload error'];
        }
        
        // Check file size
        if ($file['size'] > $max_size) {
            return ['valid' => false, 'message' => 'File size exceeds maximum allowed size'];
        }
        
        // Check file type
        $file_extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!empty($allowed_types) && !in_array($file_extension, $allowed_types)) {
            return ['valid' => false, 'message' => 'File type not allowed'];
        }
        
        // Check for malicious files
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_type = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        $dangerous_mimes = [
            'application/x-php',
            'text/x-php',
            'application/x-httpd-php',
            'application/x-httpd-php-source'
        ];
        
        if (in_array($mime_type, $dangerous_mimes)) {
            return ['valid' => false, 'message' => 'Dangerous file type detected'];
        }
        
        return ['valid' => true];
    }
    
    /**
     * Generate secure random token
     */
    public static function generateSecureToken($length = 32) {
        try {
            return bin2hex(random_bytes($length));
        } catch (Exception $e) {
            // Fallback if random_bytes is not available
            $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
            $token = '';
            for ($i = 0; $i < $length * 2; $i++) {
                $token .= $characters[rand(0, strlen($characters) - 1)];
            }
            return $token;
        }
    }
    
    /**
     * Validate URL
     */
    public static function validateURL($url) {
        $url = self::sanitizeInput($url);
        
        if (empty($url)) {
            return ['valid' => false, 'message' => 'URL is required'];
        }
        
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            return ['valid' => false, 'message' => 'Invalid URL format'];
        }
        
        // Check for dangerous protocols
        $dangerous_protocols = ['javascript', 'vbscript', 'data'];
        $url_protocol = parse_url($url, PHP_URL_SCHEME);
        
        if (in_array(strtolower($url_protocol), $dangerous_protocols)) {
            return ['valid' => false, 'message' => 'Dangerous URL protocol detected'];
        }
        
        return ['valid' => true, 'data' => $url];
    }
    
    /**
     * Bulk validation helper
     */
    public static function validateMultiple($rules) {
        $results = [];
        $all_valid = true;
        
        foreach ($rules as $field => $rule) {
            $value = $rule['value'] ?? '';
            $type = $rule['type'] ?? 'text';
            $required = $rule['required'] ?? true;
            
            // Skip validation if not required and empty
            if (!$required && empty($value)) {
                $results[$field] = ['valid' => true, 'data' => $value];
                continue;
            }
            
            // Perform validation based on type
            switch ($type) {
                case 'username':
                    $result = self::validateUsername($value);
                    break;
                case 'email':
                    $result = self::validateEmail($value);
                    break;
                case 'password':
                    $confirm = $rule['confirm'] ?? null;
                    $result = self::validatePassword($value, $confirm);
                    break;
                case 'task_title':
                    $result = self::validateTaskTitle($value);
                    break;
                case 'task_description':
                    $result = self::validateTaskDescription($value);
                    break;
                case 'url':
                    $result = self::validateURL($value);
                    break;
                case 'id':
                    $result = self::validateId($value, $rule['fieldName'] ?? 'ID');
                    break;
                default:
                    $min = $rule['min'] ?? 1;
                    $max = $rule['max'] ?? 255;
                    $result = self::validateTextLength($value, ucfirst($field), $min, $max);
            }
            
            $results[$field] = $result;
            if (!$result['valid']) {
                $all_valid = false;
            }
        }
        
        return [
            'valid' => $all_valid,
            'results' => $results,
            'errors' => array_filter($results, function($r) { return !$r['valid']; })
        ];
    }
}

/**
 * Utility function to get validated POST data
 */
function getValidatedPost($field, $default = '') {
    return isset($_POST[$field]) ? Validation::sanitizeInput($_POST[$field]) : $default;
}

/**
 * Utility function to get validated GET data
 */
function getValidatedGet($field, $default = '') {
    return isset($_GET[$field]) ? Validation::sanitizeInput($_GET[$field]) : $default;
}

/**
 * Utility function to check if request is AJAX
 */
function isAjaxRequest() {
    return !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
           strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}

/**
 * Utility function to send JSON response
 */
function sendJsonResponse($data, $status_code = 200) {
    http_response_code($status_code);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}
?>