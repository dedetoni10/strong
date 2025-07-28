#!/usr/bin/env python3
# Gunicorn configuration for handling concurrent CSV uploads

import multiprocessing
import os

# Server socket
bind = "0.0.0.0:5000"
backlog = 2048

# Worker processes
workers = max(2, multiprocessing.cpu_count())
worker_class = "sync"
worker_connections = 1000
timeout = 1200  # 20 minutes for large file processing
keepalive = 5

# Maximum request size (100MB for large CSV files)
max_requests = 1000
max_requests_jitter = 50

# Memory management
preload_app = True
reload = True
reload_engine = "auto"

# Logging
loglevel = "info"
accesslog = "-"
errorlog = "-"

# Process naming
proc_name = "strong-inventory-system"

# Memory limits
worker_tmp_dir = "/tmp"
tmp_upload_dir = "/tmp"

# Connection pooling
reuse_port = True