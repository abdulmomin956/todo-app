document.addEventListener('DOMContentLoaded', function () {
    // Update task status
    document.querySelectorAll('.update-status').forEach(button => {
        button.addEventListener('click', function () {
            const taskId = this.dataset.taskId;
            const newStatus = this.dataset.status;
            const button = this;

            fetch('../ajax/update_task.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `task_id=${taskId}&status=${newStatus}&csrf_token=<?php echo generateCSRFToken(); ?>`
            })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        location.reload(); // Simple reload for demo
                    } else {
                        alert('Error updating task');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error updating task');
                });
        });
    });

    // Delete task
    document.querySelectorAll('.delete-task').forEach(button => {
        button.addEventListener('click', function () {
            if (confirm('Are you sure you want to delete this task?')) {
                const taskId = this.dataset.taskId;
                const button = this;

                fetch('../ajax/delete_task.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `task_id=${taskId}&csrf_token=<?php echo generateCSRFToken(); ?>`
                })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            button.closest('.list-group-item').remove();
                        } else {
                            alert('Error deleting task');
                        }
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        alert('Error deleting task');
                    });
            }
        });
    });
});