// AJAX task operations
document.addEventListener('DOMContentLoaded', function () {
    // Update task status via AJAX
    document.querySelectorAll('a[href*="action=toggle_status"]').forEach(link => {
        link.addEventListener('click', function (e) {
            e.preventDefault();

            const url = new URL(this.href);
            const taskId = url.searchParams.get('id');
            const status = url.searchParams.get('status');

            fetch('../ajax/update_task.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `action=update_status&task_id=${taskId}&status=${status}&csrf_token=${getCSRFToken()}`
            })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        location.reload(); // Reload to show updated status
                    } else {
                        alert('Error updating task status');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error updating task status');
                });
        });
    });

    // Delete task via AJAX with confirmation
    document.querySelectorAll('a[href*="action=delete"]').forEach(link => {
        link.addEventListener('click', function (e) {
            e.preventDefault();

            if (confirm('Are you sure you want to delete this task?')) {
                const url = new URL(this.href);
                const taskId = url.searchParams.get('id');

                fetch('../ajax/update_task.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `action=delete_task&task_id=${taskId}&csrf_token=${getCSRFToken()}`
                })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            // Remove task from DOM
                            this.closest('.list-group-item').remove();

                            // Show success message
                            showAlert('Task deleted successfully!', 'success');

                            // Reload stats after a short delay
                            setTimeout(() => location.reload(), 1000);
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

    // Helper function to get CSRF token
    function getCSRFToken() {
        return document.querySelector('input[name="csrf_token"]')?.value || '';
    }

    // Helper function to show alerts
    function showAlert(message, type) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        document.querySelector('.container').insertBefore(alertDiv, document.querySelector('.container').firstChild);

        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alertDiv);
            bsAlert.close();
        }, 5000);
    }
});