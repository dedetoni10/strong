// Main JavaScript for Shopee Order Management System

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    initializeTooltips();
    
    // Initialize form validation
    initializeFormValidation();
    
    // Initialize auto-refresh for dashboard
    initializeAutoRefresh();
    
    // Initialize search functionality
    initializeSearch();
    
    // Initialize status update confirmations
    initializeStatusUpdates();
    
    // Initialize quantity adjustment
    initializeQuantityAdjustment();
});

// Initialize Bootstrap tooltips
function initializeTooltips() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Form validation
function initializeFormValidation() {
    const forms = document.querySelectorAll('.needs-validation');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            
            form.classList.add('was-validated');
        }, false);
    });
}

// Auto-refresh dashboard every 30 seconds
function initializeAutoRefresh() {
    if (window.location.pathname === '/') {
        setInterval(function() {
            // Only refresh if the page is visible
            if (!document.hidden) {
                fetch(window.location.href, {
                    method: 'GET',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
                .then(response => response.text())
                .then(html => {
                    // Update specific dashboard elements
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(html, 'text/html');
                    
                    // Update statistics cards
                    updateDashboardStats(doc);
                })
                .catch(error => {
                    console.error('Auto-refresh failed:', error);
                });
            }
        }, 30000); // 30 seconds
    }
}

// Update dashboard statistics
function updateDashboardStats(doc) {
    const statsCards = document.querySelectorAll('.card-body h3');
    const newStatsCards = doc.querySelectorAll('.card-body h3');
    
    statsCards.forEach((card, index) => {
        if (newStatsCards[index]) {
            card.textContent = newStatsCards[index].textContent;
        }
    });
}

// Search functionality
function initializeSearch() {
    const searchInputs = document.querySelectorAll('input[name="search"]');
    
    searchInputs.forEach(input => {
        let timeout;
        
        input.addEventListener('input', function() {
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                // Auto-submit search form after 500ms of no typing
                if (this.value.length >= 3 || this.value.length === 0) {
                    this.form.submit();
                }
            }, 500);
        });
    });
}

// Status update confirmations
function initializeStatusUpdates() {
    const statusForms = document.querySelectorAll('form[action*="update_status"]');
    
    statusForms.forEach(form => {
        form.addEventListener('submit', function(event) {
            const select = form.querySelector('select[name="status"]');
            const newStatus = select.value;
            const currentStatus = select.dataset.currentStatus;
            
            // Show confirmation for critical status changes
            if (newStatus === 'cancelled' || newStatus === 'delivered') {
                const confirmMessage = `Are you sure you want to change the status to "${newStatus}"?`;
                if (!confirm(confirmMessage)) {
                    event.preventDefault();
                    return false;
                }
            }
            
            // Show loading state
            const submitBtn = form.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Updating...';
            submitBtn.disabled = true;
            
            // Reset button state after 5 seconds (in case of network issues)
            setTimeout(() => {
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            }, 5000);
        });
    });
}

// Quantity adjustment with validation
function initializeQuantityAdjustment() {
    const quantityInputs = document.querySelectorAll('input[name="quantity"]');
    
    quantityInputs.forEach(input => {
        input.addEventListener('change', function() {
            const value = parseInt(this.value);
            
            // Validate quantity
            if (value < 0) {
                this.value = 0;
                showAlert('Quantity cannot be negative', 'warning');
            }
            
            // Warn about low stock
            const minStock = parseInt(this.dataset.minStock || 10);
            if (value <= minStock && value > 0) {
                showAlert(`Warning: Quantity is at or below minimum stock level (${minStock})`, 'warning');
            }
        });
    });
}

// Show alert messages
function showAlert(message, type = 'info') {
    const alertContainer = document.createElement('div');
    alertContainer.className = `alert alert-${type} alert-dismissible fade show`;
    alertContainer.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    // Insert at the top of the main container
    const mainContainer = document.querySelector('main.container');
    mainContainer.insertBefore(alertContainer, mainContainer.firstChild);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        if (alertContainer.parentNode) {
            alertContainer.remove();
        }
    }, 5000);
}

// Utility functions
function formatCurrency(amount) {
    return new Intl.NumberFormat('id-ID', {
        style: 'currency',
        currency: 'IDR',
        minimumFractionDigits: 0
    }).format(amount);
}

function formatDate(dateString) {
    return new Date(dateString).toLocaleDateString('id-ID', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Handle sync button loading state
document.addEventListener('click', function(event) {
    if (event.target.matches('button[type="submit"]') && 
        event.target.closest('form[action*="sync_shopee_orders"]')) {
        
        const btn = event.target;
        const originalText = btn.innerHTML;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Syncing...';
        btn.disabled = true;
        
        // Reset after 10 seconds
        setTimeout(() => {
            btn.innerHTML = originalText;
            btn.disabled = false;
        }, 10000);
    }
});

// Handle delete confirmations
document.addEventListener('click', function(event) {
    if (event.target.matches('button[type="submit"]') && 
        event.target.closest('form[action*="delete"]')) {
        
        const confirmMessage = 'Are you sure you want to delete this item? This action cannot be undone.';
        if (!confirm(confirmMessage)) {
            event.preventDefault();
            return false;
        }
    }
});

// Table sorting functionality
function initializeTableSorting() {
    const tables = document.querySelectorAll('.table-sortable');
    
    tables.forEach(table => {
        const headers = table.querySelectorAll('th[data-sortable]');
        
        headers.forEach(header => {
            header.style.cursor = 'pointer';
            header.addEventListener('click', function() {
                sortTable(table, this);
            });
        });
    });
}

function sortTable(table, header) {
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const columnIndex = Array.from(header.parentNode.children).indexOf(header);
    const currentDirection = header.dataset.sortDirection || 'asc';
    const newDirection = currentDirection === 'asc' ? 'desc' : 'asc';
    
    rows.sort((a, b) => {
        const aText = a.children[columnIndex].textContent.trim();
        const bText = b.children[columnIndex].textContent.trim();
        
        // Try to parse as numbers first
        const aNum = parseFloat(aText.replace(/[^0-9.-]/g, ''));
        const bNum = parseFloat(bText.replace(/[^0-9.-]/g, ''));
        
        if (!isNaN(aNum) && !isNaN(bNum)) {
            return newDirection === 'asc' ? aNum - bNum : bNum - aNum;
        }
        
        // Fall back to string comparison
        return newDirection === 'asc' ? 
            aText.localeCompare(bText) : 
            bText.localeCompare(aText);
    });
    
    // Clear previous sort indicators
    header.parentNode.querySelectorAll('th').forEach(th => {
        th.classList.remove('sorted-asc', 'sorted-desc');
        delete th.dataset.sortDirection;
    });
    
    // Add sort indicator
    header.classList.add(`sorted-${newDirection}`);
    header.dataset.sortDirection = newDirection;
    
    // Reorder rows
    rows.forEach(row => tbody.appendChild(row));
}

// Initialize clipboard functionality
function initializeClipboard() {
    const clipboardButtons = document.querySelectorAll('[data-clipboard-target]');
    
    clipboardButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetSelector = this.dataset.clipboardTarget;
            const target = document.querySelector(targetSelector);
            
            if (target) {
                const text = target.textContent || target.value;
                navigator.clipboard.writeText(text).then(() => {
                    showAlert('Copied to clipboard!', 'success');
                }).catch(err => {
                    console.error('Failed to copy:', err);
                    showAlert('Failed to copy to clipboard', 'danger');
                });
            }
        });
    });
}

// Export functionality
function exportTableToCSV(tableId, filename = 'export.csv') {
    const table = document.getElementById(tableId);
    if (!table) return;
    
    const rows = table.querySelectorAll('tr');
    const csvContent = [];
    
    rows.forEach(row => {
        const cols = row.querySelectorAll('td, th');
        const rowData = Array.from(cols).map(col => {
            return '"' + col.textContent.replace(/"/g, '""') + '"';
        });
        csvContent.push(rowData.join(','));
    });
    
    const csvString = csvContent.join('\n');
    const blob = new Blob([csvString], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    
    window.URL.revokeObjectURL(url);
}

// Print functionality
function printTable(tableId) {
    const table = document.getElementById(tableId);
    if (!table) return;
    
    const printWindow = window.open('', '_blank');
    const printDocument = printWindow.document;
    
    printDocument.write(`
        <html>
        <head>
            <title>Print Table</title>
            <style>
                body { font-family: Arial, sans-serif; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            ${table.outerHTML}
        </body>
        </html>
    `);
    
    printDocument.close();
    printWindow.print();
}
