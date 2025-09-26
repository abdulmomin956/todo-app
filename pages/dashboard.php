<?php
require_once '../includes/header.php';
require_once '../includes/auth.php';
require_once '../includes/tasks.php';

requireAuth();

$taskManager = new TaskManager();
$error = $success = "";

// Handle task operations
if ($_POST) {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = "Invalid CSRF token";
    } else {
        // Add new task
        if (isset($_POST['add_task'])) {
            $title = $_POST['title'] ?? '';
            $description = $_POST['description'] ?? '';
            
            $result = $taskManager->addTask($_SESSION['user_id'], $title, $description);
            if ($result === true) {
                $success = "Task added successfully!";
            } else {
                $error = $result;
            }
        }
        
        // Edit task
        if (isset($_POST['edit_task'])) {
            $task_id = $_POST['task_id'] ?? '';
            $title = $_POST['title'] ?? '';
            $description = $_POST['description'] ?? '';
            
            $result = $taskManager->editTask($task_id, $_SESSION['user_id'], $title, $description);
            if ($result === true) {
                $success = "Task updated successfully!";
            } else {
                $error = $result;
            }
        }
    }
}

// Handle GET actions (delete, status change)
if (isset($_GET['action'])) {
    switch ($_GET['action']) {
        case 'delete':
            if (isset($_GET['id'])) {
                $task_id = $_GET['id'];
                if ($taskManager->deleteTask($task_id, $_SESSION['user_id'])) {
                    $success = "Task deleted successfully!";
                } else {
                    $error = "Failed to delete task";
                }
            }
            break;
            
        case 'toggle_status':
            if (isset($_GET['id']) && isset($_GET['status'])) {
                $task_id = $_GET['id'];
                $status = $_GET['status'];
                if ($taskManager->updateTaskStatus($task_id, $_SESSION['user_id'], $status)) {
                    $success = "Task status updated!";
                } else {
                    $error = "Failed to update task status";
                }
            }
            break;
    }
    
    // Redirect to avoid form resubmission
    header("Location: dashboard.php");
    exit();
}

// Check if we're editing a task
$editing_task = null;
if (isset($_GET['edit'])) {
    $editing_task = $taskManager->getTask($_GET['edit'], $_SESSION['user_id']);
    if (!$editing_task) {
        $error = "Task not found";
    }
}

// Get user's tasks and statistics
$tasks = $taskManager->getUserTasks($_SESSION['user_id']);
$stats = $taskManager->getTaskStats($_SESSION['user_id']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Task Manager</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="../assets/css/style.css" rel="stylesheet">
    <style>
        .task-completed {
            text-decoration: line-through;
            opacity: 0.7;
        }
        .task-actions {
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        .task-item:hover .task-actions {
            opacity: 1;
        }
        .stats-card {
            transition: transform 0.3s ease;
        }
        .stats-card:hover {
            transform: translateY(-5px);
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="dashboard.php">
                <i class="fas fa-tasks me-2"></i>Task Manager
            </a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">
                    <i class="fas fa-user me-1"></i>Hello, <?php echo $_SESSION['username']; ?>
                </span>
                <a class="nav-link" href="../includes/auth.php?action=logout">
                    <i class="fas fa-sign-out-alt me-1"></i>Logout
                </a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <!-- Statistics Cards -->
        <div class="row mb-4">
            <div class="col-md-4">
                <div class="card stats-card bg-primary text-white">
                    <div class="card-body text-center">
                        <h3><?php echo $stats['total'] ?? 0; ?></h3>
                        <p class="mb-0">Total Tasks</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card stats-card bg-success text-white">
                    <div class="card-body text-center">
                        <h3><?php echo $stats['completed'] ?? 0; ?></h3>
                        <p class="mb-0">Completed</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card stats-card bg-warning text-white">
                    <div class="card-body text-center">
                        <h3><?php echo $stats['pending'] ?? 0; ?></h3>
                        <p class="mb-0">Pending</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-lg-8 mx-auto">
                <?php if ($error): ?>
                    <div class="alert alert-danger alert-dismissible fade show">
                        <?php echo $error; ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                <?php endif; ?>
                
                <?php if ($success): ?>
                    <div class="alert alert-success alert-dismissible fade show">
                        <?php echo $success; ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                <?php endif; ?>

                <!-- Add/Edit Task Form -->
                <div class="card mb-4">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">
                            <i class="fas <?php echo $editing_task ? 'fa-edit' : 'fa-plus'; ?> me-2"></i>
                            <?php echo $editing_task ? 'Edit Task' : 'Add New Task'; ?>
                        </h5>
                        <?php if ($editing_task): ?>
                            <a href="dashboard.php" class="btn btn-sm btn-outline-secondary">
                                <i class="fas fa-times me-1"></i>Cancel
                            </a>
                        <?php endif; ?>
                    </div>
                    <div class="card-body">
                        <form method="POST" id="taskForm">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            <?php if ($editing_task): ?>
                                <input type="hidden" name="task_id" value="<?php echo $editing_task['id']; ?>">
                            <?php endif; ?>
                            
                            <div class="mb-3">
                                <label for="title" class="form-label">Task Title *</label>
                                <input type="text" class="form-control" id="title" name="title" 
                                       value="<?php echo htmlspecialchars($editing_task['title'] ?? ''); ?>" 
                                       required maxlength="255">
                            </div>
                            
                            <div class="mb-3">
                                <label for="description" class="form-label">Description</label>
                                <textarea class="form-control" id="description" name="description" 
                                          rows="3" maxlength="1000"><?php echo htmlspecialchars($editing_task['description'] ?? ''); ?></textarea>
                                <div class="form-text"><span id="charCount">0</span>/1000 characters</div>
                            </div>
                            
                            <button type="submit" name="<?php echo $editing_task ? 'edit_task' : 'add_task'; ?>" 
                                    class="btn btn-<?php echo $editing_task ? 'warning' : 'primary'; ?>">
                                <i class="fas <?php echo $editing_task ? 'fa-save' : 'fa-plus'; ?> me-1"></i>
                                <?php echo $editing_task ? 'Update Task' : 'Add Task'; ?>
                            </button>
                        </form>
                    </div>
                </div>

                <!-- Tasks List -->
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">
                            <i class="fas fa-list me-2"></i>Your Tasks
                        </h5>
                        <div class="btn-group">
                            <a href="dashboard.php?filter=all" class="btn btn-sm btn-outline-primary">All</a>
                            <a href="dashboard.php?filter=pending" class="btn btn-sm btn-outline-warning">Pending</a>
                            <a href="dashboard.php?filter=completed" class="btn btn-sm btn-outline-success">Completed</a>
                        </div>
                    </div>
                    <div class="card-body">
                        <?php if (empty($tasks)): ?>
                            <div class="text-center py-4">
                                <i class="fas fa-clipboard-list fa-3x text-muted mb-3"></i>
                                <p class="text-muted">No tasks found. Add your first task above!</p>
                            </div>
                        <?php else: ?>
                            <div class="list-group">
                                <?php foreach ($tasks as $task): ?>
                                    <div class="list-group-item task-item">
                                        <div class="d-flex justify-content-between align-items-start">
                                            <div class="flex-grow-1">
                                                <div class="d-flex align-items-center mb-1">
                                                    <h6 class="mb-0 <?php echo $task['status'] == 'completed' ? 'task-completed' : ''; ?>">
                                                        <?php echo htmlspecialchars($task['title']); ?>
                                                        <?php if ($task['status'] == 'completed'): ?>
                                                            <span class="badge bg-success ms-2">Completed</span>
                                                        <?php endif; ?>
                                                    </h6>
                                                </div>
                                                
                                                <?php if (!empty($task['description'])): ?>
                                                    <p class="mb-2 text-muted small"><?php echo htmlspecialchars($task['description']); ?></p>
                                                <?php endif; ?>
                                                
                                                <small class="text-muted">
                                                    <i class="fas fa-clock me-1"></i>
                                                    Created: <?php echo date('M j, Y g:i A', strtotime($task['created_at'])); ?>
                                                    <?php if ($task['updated_at'] != $task['created_at']): ?>
                                                        • Updated: <?php echo date('M j, Y g:i A', strtotime($task['updated_at'])); ?>
                                                    <?php endif; ?>
                                                </small>
                                            </div>
                                            
                                            <div class="task-actions">
                                                <div class="btn-group btn-group-sm">
                                                    <!-- Toggle Status -->
                                                    <a href="dashboard.php?action=toggle_status&id=<?php echo $task['id']; ?>&status=<?php echo $task['status'] == 'completed' ? 'pending' : 'completed'; ?>" 
                                                       class="btn btn-<?php echo $task['status'] == 'completed' ? 'warning' : 'success'; ?>"
                                                       title="<?php echo $task['status'] == 'completed' ? 'Mark Pending' : 'Mark Complete'; ?>">
                                                        <i class="fas fa-<?php echo $task['status'] == 'completed' ? 'undo' : 'check'; ?>"></i>
                                                    </a>
                                                    
                                                    <!-- Edit -->
                                                    <a href="dashboard.php?edit=<?php echo $task['id']; ?>" 
                                                       class="btn btn-primary" title="Edit Task">
                                                        <i class="fas fa-edit"></i>
                                                    </a>
                                                    
                                                    <!-- Delete -->
                                                    <a href="dashboard.php?action=delete&id=<?php echo $task['id']; ?>" 
                                                       class="btn btn-danger" 
                                                       onclick="return confirm('Are you sure you want to delete this task?')"
                                                       title="Delete Task">
                                                        <i class="fas fa-trash"></i>
                                                    </a>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Character count for description
        const description = document.getElementById('description');
        const charCount = document.getElementById('charCount');
        
        if (description && charCount) {
            charCount.textContent = description.value.length;
            description.addEventListener('input', function() {
                charCount.textContent = this.value.length;
            });
        }

        // Auto-focus on title field when editing
        <?php if ($editing_task): ?>
            document.getElementById('title').focus();
        <?php endif; ?>

        // Auto-hide alerts after 5 seconds
        setTimeout(() => {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            });
        }, 5000);

        // Smooth scrolling to form when editing
        <?php if ($editing_task): ?>
            document.getElementById('taskForm').scrollIntoView({ behavior: 'smooth' });
        <?php endif; ?>
    </script>
</body>
</html>