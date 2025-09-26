<?php
require_once '../config/database.php';
require_once '../includes/header.php';

class TaskManager {
    private $db;
    private $conn;

    public function __construct() {
        $this->db = new Database();
        $this->conn = $this->db->getConnection();
    }

    // Add new task
    public function addTask($user_id, $title, $description = "") {
        $title = htmlspecialchars(strip_tags($title));
        $description = htmlspecialchars(strip_tags($description));

        if (empty($title)) {
            return "Task title is required";
        }

        $query = "INSERT INTO tasks (user_id, title, description) VALUES (:user_id, :title, :description)";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":user_id", $user_id);
        $stmt->bindParam(":title", $title);
        $stmt->bindParam(":description", $description);

        return $stmt->execute() ? true : "Failed to add task";
    }

    // Get user's tasks
    public function getUserTasks($user_id, $status = null) {
        $query = "SELECT * FROM tasks WHERE user_id = :user_id";
        
        if ($status) {
            $query .= " AND status = :status";
        }
        
        $query .= " ORDER BY created_at DESC";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":user_id", $user_id);
        
        if ($status) {
            $stmt->bindParam(":status", $status);
        }
        
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // Get single task by ID (for editing)
    public function getTask($task_id, $user_id) {
        $query = "SELECT * FROM tasks WHERE id = :task_id AND user_id = :user_id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":task_id", $task_id);
        $stmt->bindParam(":user_id", $user_id);
        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    // Update task status (mark complete/incomplete)
    public function updateTaskStatus($task_id, $user_id, $status) {
        $query = "UPDATE tasks SET status = :status, updated_at = CURRENT_TIMESTAMP WHERE id = :task_id AND user_id = :user_id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":status", $status);
        $stmt->bindParam(":task_id", $task_id);
        $stmt->bindParam(":user_id", $user_id);

        return $stmt->execute();
    }

    // Edit task
    public function editTask($task_id, $user_id, $title, $description) {
        $title = htmlspecialchars(strip_tags($title));
        $description = htmlspecialchars(strip_tags($description));

        if (empty($title)) {
            return "Task title is required";
        }

        $query = "UPDATE tasks SET title = :title, description = :description, updated_at = CURRENT_TIMESTAMP WHERE id = :task_id AND user_id = :user_id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":title", $title);
        $stmt->bindParam(":description", $description);
        $stmt->bindParam(":task_id", $task_id);
        $stmt->bindParam(":user_id", $user_id);

        return $stmt->execute() ? true : "Failed to update task";
    }

    // Delete task
    public function deleteTask($task_id, $user_id) {
        $query = "DELETE FROM tasks WHERE id = :task_id AND user_id = :user_id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":task_id", $task_id);
        $stmt->bindParam(":user_id", $user_id);

        return $stmt->execute();
    }

    // Get task statistics
    public function getTaskStats($user_id) {
        $query = "SELECT 
                    COUNT(*) as total,
                    SUM(status = 'completed') as completed,
                    SUM(status = 'pending') as pending
                  FROM tasks 
                  WHERE user_id = :user_id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":user_id", $user_id);
        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
}
?>