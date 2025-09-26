<?php
require_once '../includes/header.php';
require_once '../includes/tasks.php';

requireAuth();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        echo json_encode(['success' => false, 'message' => 'Invalid CSRF token']);
        exit();
    }

    $taskManager = new TaskManager();
    
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'update_status':
                if (isset($_POST['task_id']) && isset($_POST['status'])) {
                    $success = $taskManager->updateTaskStatus($_POST['task_id'], $_SESSION['user_id'], $_POST['status']);
                    echo json_encode(['success' => $success]);
                }
                break;
                
            case 'delete_task':
                if (isset($_POST['task_id'])) {
                    $success = $taskManager->deleteTask($_POST['task_id'], $_SESSION['user_id']);
                    echo json_encode(['success' => $success]);
                }
                break;
                
            default:
                echo json_encode(['success' => false, 'message' => 'Invalid action']);
        }
    }
    exit();
}