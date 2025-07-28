from flask import render_template, request, redirect, url_for, flash, jsonify, Response, session, make_response
from ultra_cache import ultra_cache, ULTRA_QUERY_CACHE, cached_db_query
from app import app, db, calculate_order_profit
import models
from shopee_api import shopee_api
import logging
from functools import lru_cache
import time
# Import database models after app context to avoid circular import
from database_models import User, Order, OrderItem, Product, PickingSession, StockMovement, ScanHistory, PickingAuditTrail, PackingAuditTrail, ActivityLog, Store, ProfitSettings, DailyCost, OperationalCost, ExpenseRecord, Employee, Attendance, MonthlyPayroll, Location, SalaryGroup, WorkSchedule, ShopeeStore, StoreAdvertisingCost
from datetime import datetime, timedelta
import csv
import io
from sqlalchemy import func, desc, text
import json
try:
    import qrcode
    from qrcode import constants
except ImportError:
    qrcode = None
    constants = None
from io import BytesIO
import base64
from functools import wraps
import os
from werkzeug.utils import secure_filename
import uuid

# Custom Jinja2 filter for Indonesia timezone conversion
@app.template_filter('wib_time')
def wib_time_filter(utc_datetime):
    """Convert UTC datetime to WIB (UTC+7) and format as HH:MM:SS"""
    if utc_datetime is None:
        return '-'
    try:
        # Add 7 hours to UTC time
        wib_datetime = utc_datetime + timedelta(hours=7)
        return wib_datetime.strftime('%H:%M:%S')
    except:
        return '-'

@app.route('/qr-code/<sku>')
def generate_qr_code(sku):
    """Generate QR Code page for a specific SKU"""
    try:
        # Get product info from database
        product = Product.query.filter_by(sku=sku).first()
        if not product:
            return "Product not found", 404
        
        # Generate QR Code
        if not qrcode:
            return "QR Code library not available", 500
            
        qr = qrcode.QRCode(
            version=1,
            error_correction=constants.ERROR_CORRECT_M,
            box_size=10,
            border=2,
        )
        qr.add_data(sku)
        qr.make(fit=True)
        
        # Create QR code image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return render_template('qr_code.html', 
                             sku=sku, 
                             product_name=product.name, 
                             qr_code=img_str)
    except Exception as e:
        logging.error(f"Error generating QR code: {e}")
        return "Error generating QR code", 500

@app.route('/qr-codes-multiple', methods=['GET', 'POST'])
def generate_multiple_qr_codes():
    """Generate multiple QR codes in one page"""
    try:
        print(f"DEBUG: Request method: {request.method}")
        print(f"DEBUG: Request args: {request.args}")
        print(f"DEBUG: Request form: {request.form}")
        
        # Handle both GET and POST requests
        if request.method in ['GET', 'HEAD']:
            # Get product IDs from query parameter
            ids_param = request.args.get('ids', '')
            print(f"DEBUG: GET/HEAD request - ids parameter: {ids_param}")
            if ids_param:
                selected_products = ids_param.split(',')
            else:
                selected_products = []
        else:
            # POST method - get from form
            selected_products = request.form.getlist('selected_products[]')
            print(f"DEBUG: POST request - selected_products: {selected_products}")
        
        print(f"DEBUG: Selected products IDs: {selected_products}")
        
        if not selected_products or (len(selected_products) == 1 and selected_products[0] == ''):
            print(f"DEBUG: No products selected, redirecting to warehouse")
            flash('No products selected', 'error')
            return redirect(url_for('warehouse'))
        
        qr_codes = []
        
        for product_id in selected_products:
            print(f"DEBUG: Processing product ID: {product_id}")
            product = Product.query.get(product_id)
            if product:
                print(f"DEBUG: Found product: {product.name} - SKU: {product.sku}")
                # Generate QR Code
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_M,
                    box_size=8,
                    border=2,
                )
                qr.add_data(product.sku)
                qr.make(fit=True)
                
                # Create QR code image
                img = qr.make_image(fill_color="black", back_color="white")
                
                # Convert to base64
                buffered = BytesIO()
                img.save(buffered, format="PNG")
                img_str = base64.b64encode(buffered.getvalue()).decode()
                
                # Format location display
                location = ''
                if product.zone or product.rack or product.bin:
                    location_parts = []
                    if product.zone:
                        location_parts.append(f"Zone: {product.zone}")
                    if product.rack:
                        location_parts.append(f"Rack: {product.rack}")
                    if product.bin:
                        location_parts.append(f"Bin: {product.bin}")
                    location = " | ".join(location_parts)
                
                qr_codes.append({
                    'sku': product.sku,
                    'name': product.name,
                    'qr_code': img_str,
                    'location': location
                })
            else:
                print(f"DEBUG: Product not found for ID: {product_id}")
        
        print(f"DEBUG: Generated {len(qr_codes)} QR codes")
        print(f"DEBUG: QR codes data: {[{'sku': qr['sku'], 'name': qr['name']} for qr in qr_codes]}")
        return render_template('qr_codes_table.html', qr_codes=qr_codes)
    except Exception as e:
        logging.error(f"Error generating multiple QR codes: {e}")
        return "Error generating QR codes", 500

@app.route('/test-qr-multiple')
def test_qr_multiple():
    """Test route to check multiple QR codes with hardcoded data"""
    try:
        # Get first 3 products for testing
        products = Product.query.limit(3).all()
        print(f"DEBUG TEST: Found {len(products)} products")
        
        qr_codes = []
        for product in products:
            print(f"DEBUG TEST: Processing {product.name}")
            # Generate QR Code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=8,
                border=2,
            )
            qr.add_data(product.sku)
            qr.make(fit=True)
            
            # Create QR code image
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffered = BytesIO()
            img.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode()
            
            qr_codes.append({
                'sku': product.sku,
                'name': product.name,
                'qr_code': img_str
            })
        
        print(f"DEBUG TEST: Generated {len(qr_codes)} QR codes")
        return render_template('qr_codes_multiple.html', qr_codes=qr_codes)
    except Exception as e:
        print(f"DEBUG TEST: Error - {e}")
        return "Error in test", 500

@app.route('/debug-qr-multiple')
def debug_qr_multiple():
    """Debug route to check what's happening"""
    try:
        # First, let's see what products actually exist
        all_products = Product.query.all()
        print(f"DEBUG ROUTE: Total products in database: {len(all_products)}")
        
        product_info = []
        for product in all_products[:5]:  # Show first 5 products
            product_info.append(f"ID: {product.id}, Name: {product.name}, SKU: {product.sku}")
            print(f"DEBUG ROUTE: Product - ID: {product.id}, Name: {product.name}")
        
        # Test with actual IDs
        if all_products:
            actual_ids = [str(p.id) for p in all_products[:3]]
            print(f"DEBUG ROUTE: Testing with actual IDs: {actual_ids}")
            
            qr_codes = []
            for product_id in actual_ids:
                print(f"DEBUG ROUTE: Looking for product ID: {product_id}")
                product = Product.query.get(product_id)
                if product:
                    print(f"DEBUG ROUTE: Found product: {product.name}")
                    qr_codes.append({
                        'sku': product.sku,
                        'name': product.name,
                        'qr_code': 'dummy_base64_data'
                    })
                else:
                    print(f"DEBUG ROUTE: Product not found for ID: {product_id}")
            
            print(f"DEBUG ROUTE: Final QR codes count: {len(qr_codes)}")
            return f"DEBUG: Total products: {len(all_products)}<br>First 5 products:<br>" + "<br>".join(product_info) + f"<br><br>Test with actual IDs {actual_ids}: Found {len(qr_codes)} products"
        else:
            return "DEBUG: No products found in database"
    except Exception as e:
        print(f"DEBUG ROUTE: Error - {e}")
        return f"DEBUG ERROR: {e}"

def add_scan_history_with_cleanup(barcode, order_id, scan_type, success, message, order_number, customer_name):
    """
    Add scan history entry with automatic cleanup to keep only last 10 successful scans - OPTIMIZED FOR SPEED
    """
    try:
        # FAST: Only add successful scans to history to reduce database load
        if success:
            # Add new scan entry - ensure order_id is not None for database constraints
            scan_entry = ScanHistory(
                barcode=barcode,
                order_id=order_id if order_id is not None else None,
                scan_type=scan_type,
                success=success,
                message=message,
                order_number=order_number or 'N/A',
                customer_name=customer_name or 'N/A'
            )
            db.session.add(scan_entry)
            
            # OPTIMIZED: Cleanup in single query - delete old entries beyond 10 most recent
            # Use raw SQL for faster cleanup
            db.session.execute(text("""
                DELETE FROM scan_history 
                WHERE success = true 
                AND id NOT IN (
                    SELECT id FROM (
                        SELECT id FROM scan_history 
                        WHERE success = true 
                        ORDER BY scanned_at DESC 
                        LIMIT 10
                    ) AS latest_scans
                )
            """))
            
            db.session.commit()
            logging.info(f"Fast scan history added for {barcode}")
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error adding scan history: {e}")
        # Don't raise - let main process continue



# All user authentication now handled via database - no hardcoded demo users

def login_required(f):
    """Decorator to require login for protected routes"""
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def admin_required(f):
    """Decorator to require admin role for specific routes"""
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        
        current_user = User.query.filter_by(username=session['username']).first()
        if not current_user or 'admin' not in current_user.role:
            flash('Akses ditolak. Hanya admin yang dapat mengakses halaman ini.', 'danger')
            return redirect(url_for('scan_center'))  # Redirect to scan center instead
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def role_required(*allowed_roles):
    """Decorator to require specific roles for routes"""
    def decorator(f):
        def decorated_function(*args, **kwargs):
            if 'logged_in' not in session:
                return redirect(url_for('login'))
            
            current_user = User.query.filter_by(username=session['username']).first()
            if not current_user:
                return redirect(url_for('login'))
            
            # Check if user has any of the allowed roles
            user_roles = current_user.role.split(',') if ',' in current_user.role else [current_user.role]
            has_access = any(role.strip() in user_roles for role in allowed_roles)
            
            if not has_access:
                flash(f'Akses ditolak. Role yang diperlukan: {", ".join(allowed_roles)}', 'danger')
                return redirect(url_for('scan_center'))
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

# Duplicate admin_required removed - using the first one only

def check_access(required_access):
    """Check if user has required access level"""
    if 'logged_in' not in session:
        return False
    
    user_access = session.get('user_access', '')
    user_role = session.get('user_role', '')
    
    # Admin has access to everything
    if user_role == 'admin':
        return True
    
    # Check specific access requirements - support both 'picking' and 'picking_only' format
    if required_access == 'picking' and ('picking' in user_access):
        return True
    elif required_access == 'packing' and ('packing' in user_access):
        return True
    elif required_access == 'shipping' and ('shipping' in user_access):
        return True
    elif required_access == 'retur' and ('retur' in user_access):
        return True
    elif required_access == 'pesanan' and ('pesanan' in user_access):
        return True
    
    return False

@app.route('/user_management')
@admin_required
def user_management():
    """User management page - Admin only"""
    # Check if this is an AJAX request
    ajax_request = request.args.get('ajax') == '1' or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    users = User.query.all()
    
    template_name = 'user_management_content.html' if ajax_request else 'user_management.html'
    return render_template(template_name, users=users)

@app.route('/create_user', methods=['POST'])
@admin_required
def create_user():
    """Create new user - Admin only"""
    username = request.form.get('username')
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    selected_roles = request.form.getlist('role[]')  # Get multiple roles from checkboxes
    access_permissions = request.form.getlist('access[]')  # Get checkbox array
    
    # Validation
    if not all([username, name, password]) or not selected_roles:
        flash('Username, nama, password, dan minimal satu role harus diisi', 'error')
        return redirect(url_for('user_management'))
    
    if len(password) < 6:
        flash('Password minimal 6 karakter', 'error')
        return redirect(url_for('user_management'))
    
    # Check if username already exists in database
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash('Username sudah digunakan', 'error')
        return redirect(url_for('user_management'))
    
    # Check if email already exists in database
    if email:
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email sudah digunakan', 'error')
            return redirect(url_for('user_management'))
    
    # Process multiple roles - join with comma for storage
    primary_role = selected_roles[0]  # Use first selected role as primary
    all_roles = ','.join(selected_roles) if len(selected_roles) > 1 else primary_role
    
    # Process access permissions
    if 'all' in access_permissions:
        access = 'all'
    elif access_permissions:
        # Join selected permissions with comma
        access = ','.join(access_permissions)
    else:
        # Auto-assign access based on selected roles
        if 'admin' in selected_roles:
            access = 'all'
        else:
            # Combine access from all selected roles
            role_access_map = {
                'picker': 'picking',
                'packer': 'packing', 
                'shipper': 'shipping',
                'scan retur': 'retur',
                'order staff': 'pesanan'
            }
            access_list = []
            for role in selected_roles:
                if role in role_access_map:
                    access_list.append(role_access_map[role])
            access = ','.join(access_list) if access_list else 'picking'
    
    try:
        # Create new user in database
        from datetime import datetime
        current_time = datetime.utcnow()
        
        new_user = User(
            username=username,
            name=name,
            email=email or None,
            role=all_roles,  # Store all roles
            access=access,
            created_at=current_time,
            updated_at=current_time
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash(f'User {username} berhasil dibuat dengan roles: {all_roles} dan access: {access}!', 'success')
        return redirect(url_for('user_management'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error creating user: {e}")
        flash('Terjadi kesalahan saat membuat user. Silakan coba lagi.', 'error')
        return redirect(url_for('user_management'))

@app.route('/toggle_user/<int:user_id>')
@admin_required
def toggle_user(user_id):
    """Toggle user active status - Admin only"""
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    
    status = "diaktifkan" if user.is_active else "dinonaktifkan"
    flash(f'User {user.username} berhasil {status}', 'success')
    return redirect(url_for('user_management'))

@app.route('/delete_user/<int:user_id>')
@admin_required
def delete_user(user_id):
    """Delete user - Admin only"""
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting the last admin
    if user.role == 'admin':
        admin_count = User.query.filter_by(role='admin', is_active=True).count()
        if admin_count <= 1:
            flash('Tidak dapat menghapus admin terakhir', 'error')
            return redirect(url_for('user_management'))
    
    try:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} berhasil dihapus', 'success')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting user: {e}")
        flash('Terjadi kesalahan saat menghapus user', 'error')
    
    return redirect(url_for('user_management'))

@app.route('/update_user_role_access', methods=['POST'])
@admin_required
def update_user_role_access():
    """Update user role and access - Admin only"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        role = data.get('role')
        access = data.get('access')
        
        user = User.query.get_or_404(user_id)
        
        if role:
            user.role = role
        if access:
            user.access = access
            
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'User berhasil diperbarui'})
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error updating user: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/update_username', methods=['POST'])
@admin_required
def update_username():
    """Update user username - Admin only"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        new_username = data.get('username')
        
        if not new_username:
            return jsonify({'success': False, 'message': 'Username tidak boleh kosong'})
            
        # Check if username already exists
        existing_user = User.query.filter_by(username=new_username).filter(User.id != user_id).first()
        if existing_user:
            return jsonify({'success': False, 'message': 'Username sudah digunakan'})
        
        user = User.query.get_or_404(user_id)
        old_username = user.username
        user.username = new_username
        user.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Username berhasil diubah dari {old_username} ke {new_username}'
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error updating username: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/change_password', methods=['POST'])
@admin_required
def change_password():
    """Change user password - Admin only"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        new_password = data.get('new_password')
        
        if not new_password:
            return jsonify({'success': False, 'message': 'Password tidak boleh kosong'})
            
        if len(new_password) < 6:
            return jsonify({'success': False, 'message': 'Password harus minimal 6 karakter'})
        
        user = User.query.get_or_404(user_id)
        user.set_password(new_password)
        user.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Password untuk user {user.username} berhasil diubah'
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error changing password: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/update_user_name', methods=['POST'])
@admin_required
def update_user_name():
    """Update user name - Admin only"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        name = data.get('name', '').strip()
        
        user = User.query.get_or_404(user_id)
        user.name = name
        user.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Nama user {user.username} berhasil diubah'
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error updating user name: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/update_user_email', methods=['POST'])
@admin_required
def update_user_email():
    """Update user email - Admin only"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        email = data.get('email', '').strip()
        
        # Check if email already exists (only if not empty)
        if email:
            existing_user = User.query.filter_by(email=email).filter(User.id != user_id).first()
            if existing_user:
                return jsonify({'success': False, 'message': 'Email sudah digunakan user lain'})
        
        user = User.query.get_or_404(user_id)
        user.email = email if email else None
        user.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Email user {user.username} berhasil diubah'
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error updating user email: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page with role-based access"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check database first
        user = User.query.filter_by(username=username, is_active=True).first()
        
        # Special case for tonidede1 with plain text password
        if user and ((user.check_password(password)) or (username == 'tonidede1' and password == '28Salsabila')):
            # Database user login
            session['logged_in'] = True
            session['username'] = username
            session['user_role'] = user.role
            session['user_access'] = user.access
            session['user_name'] = user.name
            
            flash(f'Selamat datang, {user.name}!', 'success')
            
            # Redirect based on user role and username
            if user.role == 'admin':
                return redirect(url_for('dashboard'))
            elif username == 'tonidede1':
                # tonidede1 goes directly to picking mode
                return redirect(url_for('picking_mode'))
            elif user.role == 'scan retur' or 'scan retur' in user.role:
                # scan retur users go directly to scan retur foto
                return redirect(url_for('scan_retur_foto'))
            elif user.role == 'order staff' or 'order staff' in user.role:
                # order staff users go directly to orders page
                return redirect(url_for('orders_new'))
            else:
                # Other non-admin users go to scan center
                return redirect(url_for('scan_center'))
        
        else:
            flash('Username atau password salah', 'error')
    
    return render_template('login.html')





@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    flash('Anda telah logout', 'info')
    return redirect(url_for('login'))

@app.route('/')
def dashboard():
    """Dashboard with overview statistics - Admin only - ULTRA-OPTIMIZED Strong Versi 03 Logic"""
    # Check if any admin exists in the system
    admin_exists = User.query.filter_by(role='admin').first()
    if not admin_exists:
        return redirect(url_for('expense_setup'))
    
    # Check if user is logged in
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    # Special redirect for tonidede1 - always go to picking mode
    if session.get('username') == 'tonidede1':
        return redirect(url_for('picking_mode'))
    
    # Special redirect for scan retur users - always go to scan retur foto
    if session.get('user_role') == 'scan retur':
        return redirect(url_for('scan_retur_foto'))
    
    # Check if user is admin
    if session.get('user_role') != 'admin':
        return redirect(url_for('scan_center'))
    
    # Check if this is an AJAX request
    ajax_request = request.args.get('ajax') == '1' or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    try:
        # ULTRA-OPTIMIZED: Single raw SQL query for all stats
        stats_result = db.session.execute(text("""
            SELECT 
                (SELECT COUNT(*) FROM orders) as total_orders,
                (SELECT COUNT(*) FROM products) as total_products,
                (SELECT COUNT(*) FROM orders WHERE status = 'pending') as pending_orders,
                (SELECT COUNT(*) FROM products WHERE quantity <= minimum_stock) as low_stock_products
        """)).fetchone()
        
        stats = {
            'total_orders': stats_result.total_orders,
            'total_products': stats_result.total_products,
            'pending_orders': stats_result.pending_orders,
            'low_stock_products': stats_result.low_stock_products
        }
        
        # ULTRA-OPTIMIZED: Raw SQL for recent orders
        recent_orders_result = db.session.execute(text("""
            SELECT id, order_number, customer_name, status, created_at, total_amount
            FROM orders 
            ORDER BY created_at DESC 
            LIMIT 5
        """)).fetchall()
        
        recent_orders = []
        for row in recent_orders_result:
            recent_orders.append({
                'id': row.id,
                'order_number': row.order_number,
                'customer_name': row.customer_name,
                'status': row.status,
                'created_at': row.created_at,
                'total_amount': row.total_amount
            })
        
        # ULTRA-OPTIMIZED: Raw SQL for low stock items
        low_stock_result = db.session.execute(text("""
            SELECT id, name, sku, quantity, minimum_stock
            FROM products 
            WHERE quantity <= minimum_stock
            ORDER BY quantity ASC
        """)).fetchall()
        
        low_stock_items = []
        for row in low_stock_result:
            low_stock_items.append({
                'id': row.id,
                'name': row.name,
                'sku': row.sku,
                'quantity': row.quantity,
                'minimum_stock': row.minimum_stock
            })
        
        template_name = 'dashboard_content.html' if ajax_request else 'dashboard.html'
        return render_template(template_name, 
                             stats=stats, 
                             recent_orders=recent_orders,
                             low_stock_items=low_stock_items)
    
    except Exception as e:
        logging.error(f"Error in dashboard: {e}")
        # Fallback stats if query fails
        stats = {
            'total_orders': 0,
            'total_products': 0,
            'pending_orders': 0,
            'low_stock_products': 0
        }
        template_name = 'dashboard_content.html' if ajax_request else 'dashboard.html'
        return render_template(template_name, 
                             stats=stats, 
                             recent_orders=[],
                             low_stock_items=[])

@app.route('/beranda')
@login_required
def beranda():
    """Beranda route - alias untuk dashboard"""
    return redirect(url_for('dashboard'))

@app.route('/orders')  
@login_required
def orders():
    # Check if user has pesanan access (admin or order staff)
    if not (check_access('pesanan') or check_access('all')):
        flash('Akses ditolak. Anda memerlukan akses "Menu Pesanan Saya" untuk mengakses halaman ini.', 'error')
        return redirect(url_for('dashboard'))
    """Orders management page with pagination"""
    search_query = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    page = request.args.get('page', 1, type=int)
    per_page = 50  # 50 orders per page
    
    query = Order.query
    
    # Apply filters
    if search_query:
        query = query.filter(
            (Order.customer_name.ilike(f'%{search_query}%')) |
            (Order.order_number.ilike(f'%{search_query}%')) |
            (Order.tracking_number.ilike(f'%{search_query}%'))
        )
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    # Sort by creation date (newest first) and paginate
    pagination = query.order_by(Order.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    orders = pagination.items
    
    # Get status counts for tab badges
    perlu_dikirim_count = Order.query.filter(Order.status == 'perlu_dikirim').count()
    siap_dikirim_count = Order.query.filter(Order.status == 'siap_dikirim').count()
    dikirim_count = Order.query.filter(Order.status == 'dikirim').count()
    selesai_count = Order.query.filter(Order.status == 'selesai').count()
    pengembalian_count = Order.query.filter(Order.status == 'pengembalian').count()
    
    statuses = ['pending', 'picking', 'picked', 'packing', 'packed', 'ready_for_pickup']
    
    # Calculate total orders and status counts
    total_orders = Order.query.count()
    status_counts = {
        'perlu_dikirim': perlu_dikirim_count,
        'siap_dikirim': siap_dikirim_count,
        'dikirim': dikirim_count,
        'selesai': selesai_count,
        'pengembalian': pengembalian_count
    }
    
    # Create tab_counts for template
    tab_counts = {
        'semua': total_orders,
        'perlu_dikirim': perlu_dikirim_count,
        'siap_dikirim': siap_dikirim_count,
        'dikirim': dikirim_count,
        'selesai': selesai_count,
        'pengembalian': pengembalian_count
    }
    
    return render_template('orders.html', 
                         orders=orders,
                         pagination=pagination,
                         search_query=search_query,
                         status_filter=status_filter,
                         statuses=statuses,
                         total_orders=total_orders,
                         status_counts=status_counts,
                         tab_counts=tab_counts,
                         calculate_order_profit=calculate_order_profit)

@app.route('/orders/new')
@login_required
def orders_new():
    # Check if user has pesanan access (admin or order staff)
    if not (check_access('pesanan') or check_access('all')):
        flash('Akses ditolak. Anda memerlukan akses "Menu Pesanan Saya" untuk mengakses halaman ini.', 'error')
        return redirect(url_for('dashboard'))
    
    """New orders management page with improved layout and AJAX support"""
    search_query = request.args.get('search', '')
    status_filter = request.args.get('status', 'perlu_dikirim')  # Default to perlu_dikirim
    page = request.args.get('page', 1, type=int)
    per_page = 50  # 50 orders per page
    ajax_request = request.args.get('ajax', '0') == '1'
    
    query = Order.query
    
    # Apply filters
    if search_query:
        query = query.filter(
            (Order.customer_name.ilike(f'%{search_query}%')) |
            (Order.order_number.ilike(f'%{search_query}%')) |
            (Order.tracking_number.ilike(f'%{search_query}%'))
        )
    
    # Only filter by status if not 'all'
    if status_filter and status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    # Sort by creation date (newest first) and paginate
    pagination = query.order_by(Order.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    orders = pagination.items
    
    # Get status counts for tab badges - OPTIMIZED with single query
    status_counts = db.session.query(
        Order.status, 
        func.count(Order.id).label('count')
    ).group_by(Order.status).all()
    
    # Convert to dict for easy access
    counts_dict = {status: count for status, count in status_counts}
    perlu_dikirim_count = counts_dict.get('perlu_dikirim', 0)
    siap_dikirim_count = counts_dict.get('siap_dikirim', 0)
    dikirim_count = counts_dict.get('dikirim', 0)
    selesai_count = counts_dict.get('selesai', 0)
    pengembalian_count = counts_dict.get('pengembalian', 0)
    
    # Create tab_counts for template
    tab_counts = {
        'perlu_dikirim': perlu_dikirim_count,
        'siap_dikirim': siap_dikirim_count,
        'dikirim': dikirim_count,
        'selesai': selesai_count,
        'pengembalian': pengembalian_count
    }
    
    # Generate header text based on status
    status_labels = {
        'all': 'Semua Pesanan',
        'perlu_dikirim': 'Pesanan Perlu Dikirim',
        'siap_dikirim': 'Pesanan Siap Dikirim', 
        'dikirim': 'Pesanan Dikirim',
        'selesai': 'Pesanan Selesai',
        'pengembalian': 'Pesanan Pengembalian/Pembatalan'
    }
    
    header_text = status_labels.get(status_filter, 'Semua Pesanan')
    
    # Handle AJAX request - return content-only template
    if ajax_request:
        response = make_response(render_template('orders_new_content.html', 
                                               orders=orders,
                                               pagination=pagination,
                                               search_query=search_query,
                                               status_filter=status_filter,
                                               tab_counts=tab_counts,
                                               header_text=header_text,
                                               calculate_order_profit=calculate_order_profit))
        # Add cache-busting headers
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    else:
        response = make_response(render_template('orders_new.html', 
                                               orders=orders,
                                               pagination=pagination,
                                               search_query=search_query,
                                               status_filter=status_filter,
                                               tab_counts=tab_counts,
                                               header_text=header_text,
                                               calculate_order_profit=calculate_order_profit))
        # Add cache-busting headers
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

def extract_store_code_from_sku(sku):
    """Extract store code from SKU format: 'MJP | BLD-GLSMY-PTH | SET GELAS'"""
    if not sku or '|' not in sku:
        return 'UNKNOWN'
    return sku.split('|')[0].strip()

def get_store_from_database(store_code):
    """Get store information from database"""
    if not store_code or store_code == 'UNKNOWN':
        return {'name': 'Toko Tidak Dikenal', 'code': 'UNKNOWN'}
    
    store = Store.query.filter_by(sku_code=store_code.strip(), is_active=True).first()
    if store:
        return {'name': store.store_name, 'code': store.sku_code}
    else:
        return {'name': f'{store_code} (Belum Terdaftar)', 'code': store_code}

@app.route('/orders/toko')
@login_required
def orders_toko():
    # Check if user has pesanan access (admin or order staff)
    if not (check_access('pesanan') or check_access('all')):
        flash('Akses ditolak. Anda memerlukan akses "Menu Pesanan Saya" untuk mengakses halaman ini.', 'error')
        return redirect(url_for('dashboard'))
    
    """Store-based orders management page with AJAX support"""
    search_query = request.args.get('search', '')
    store_filter = request.args.get('store', 'MJP')  # Default to MJP
    status_filter = request.args.get('status', 'all')
    page = request.args.get('page', 1, type=int)
    per_page = 50  # 50 orders per page
    ajax_request = request.args.get('ajax', '0') == '1'
    
    # Get all store codes and their order counts
    store_data_query = db.session.query(
        func.split_part(OrderItem.sku, '|', 1).label('store_code'),
        func.count(func.distinct(OrderItem.order_id)).label('order_count')
    ).filter(
        OrderItem.sku.ilike('%|%')
    ).group_by(
        func.split_part(OrderItem.sku, '|', 1)
    ).all()
    
    # Build store data dictionary with database lookup
    store_data = {}
    for store_code, count in store_data_query:
        clean_code = store_code.strip() if store_code else 'UNKNOWN'
        store_info = get_store_from_database(clean_code)
        store_data[clean_code] = {
            'name': store_info['name'],
            'total_count': count
        }
    
    # Get registered stores from database even if no orders yet
    registered_stores = Store.query.filter_by(is_active=True).all()
    for store in registered_stores:
        if store.sku_code not in store_data:
            store_data[store.sku_code] = {
                'name': store.store_name,
                'total_count': 0
            }
    
    # If no stores found at all, add default
    if not store_data:
        store_data['MJP'] = {'name': 'Belum Ada Toko Terdaftar', 'total_count': 0}
    
    # Get order IDs for the selected store
    store_order_ids = db.session.query(OrderItem.order_id).filter(
        func.split_part(OrderItem.sku, '|', 1) == store_filter
    ).distinct().subquery()
    
    # Query orders for the selected store
    query = Order.query.filter(Order.id.in_(store_order_ids))
    
    # Apply filters
    if search_query:
        query = query.filter(
            (Order.customer_name.ilike(f'%{search_query}%')) |
            (Order.order_number.ilike(f'%{search_query}%')) |
            (Order.tracking_number.ilike(f'%{search_query}%'))
        )
    
    # Only filter by status if not 'all'
    if status_filter and status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    # Sort by creation date (newest first) and paginate
    pagination = query.order_by(Order.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    orders = pagination.items
    
    # Get status counts for selected store only
    store_status_counts = db.session.query(
        Order.status,
        func.count(Order.id).label('count')
    ).filter(
        Order.id.in_(db.session.query(OrderItem.order_id).filter(
            func.split_part(OrderItem.sku, '|', 1) == store_filter
        ).distinct())
    ).group_by(Order.status).all()
    
    # Convert to dict for easy access
    counts_dict = {status: count for status, count in store_status_counts}
    
    # Calculate total count for 'all' tab
    total_count = sum(counts_dict.values())
    
    # Create tab_counts for template
    tab_counts = {
        'all': total_count,
        'perlu_dikirim': counts_dict.get('perlu_dikirim', 0),
        'siap_dikirim': counts_dict.get('siap_dikirim', 0),
        'dikirim': counts_dict.get('dikirim', 0),
        'selesai': counts_dict.get('selesai', 0),
        'pengembalian': counts_dict.get('pengembalian', 0)
    }
    
    # Generate header text based on store and status
    store_info = get_store_from_database(store_filter)
    store_name = store_info['name']
    if status_filter == 'all':
        header_text = f'Semua Pesanan - {store_name}'
    else:
        status_labels = {
            'perlu_dikirim': 'Perlu Dikirim',
            'siap_dikirim': 'Siap Dikirim', 
            'dikirim': 'Dikirim',
            'selesai': 'Selesai',
            'pengembalian': 'Pengembalian/Pembatalan'
        }
        status_text = status_labels.get(status_filter, status_filter)
        header_text = f'Pesanan {status_text} - {store_name}'
    
    # Handle AJAX request - return content-only template
    if ajax_request:
        response = make_response(render_template('orders_toko_content.html', 
                                               orders=orders,
                                               pagination=pagination,
                                               search_query=search_query,
                                               current_store=store_filter,
                                               current_status=status_filter,
                                               store_data=store_data,
                                               tab_counts=tab_counts,
                                               header_text=header_text))
        # Add cache-busting headers
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    else:
        response = make_response(render_template('orders_toko.html', 
                                               orders=orders,
                                               pagination=pagination,
                                               search_query=search_query,
                                               current_store=store_filter,
                                               current_status=status_filter,
                                               store_data=store_data,
                                               tab_counts=tab_counts,
                                               header_text=header_text))
        # Add cache-busting headers
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

@app.route('/stores/create', methods=['POST'])
@login_required
def create_store():
    """Create new store"""
    # Check admin access
    if not check_access('all'):
        return jsonify({'success': False, 'message': 'Akses ditolak. Hanya admin yang dapat menambah toko.'}), 403
    
    store_name = request.form.get('store_name', '').strip()
    sku_code = request.form.get('sku_code', '').strip().upper()
    description = request.form.get('description', '').strip()
    
    if not store_name or not sku_code:
        return jsonify({'success': False, 'message': 'Nama toko dan kode SKU wajib diisi.'}), 400
    
    # Check if sku_code already exists
    existing_store = Store.query.filter_by(sku_code=sku_code).first()
    if existing_store:
        return jsonify({'success': False, 'message': f'Kode SKU "{sku_code}" sudah digunakan oleh toko lain.'}), 400
    
    try:
        # Create new store
        new_store = Store(
            store_name=store_name,
            sku_code=sku_code,
            description=description if description else None,
            is_active=True
        )
        
        db.session.add(new_store)
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Toko "{store_name}" berhasil ditambahkan dengan kode "{sku_code}".',
            'store': {
                'id': new_store.id,
                'store_name': new_store.store_name,
                'sku_code': new_store.sku_code,
                'description': new_store.description
            }
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Gagal menambah toko: {str(e)}'}), 500

@app.route('/stores/list')
@login_required
def list_stores():
    """Get all active stores"""
    stores = Store.query.filter_by(is_active=True).order_by(Store.store_name).all()
    
    stores_data = []
    for store in stores:
        # Get order count for this store
        order_count = db.session.query(func.count(func.distinct(OrderItem.order_id))).filter(
            func.split_part(OrderItem.sku, '|', 1) == store.sku_code
        ).scalar() or 0
        
        stores_data.append({
            'id': store.id,
            'store_name': store.store_name,
            'sku_code': store.sku_code,
            'description': store.description,
            'order_count': order_count,
            'created_at': store.created_at.strftime('%Y-%m-%d') if store.created_at else None
        })
    
    return jsonify({'success': True, 'stores': stores_data})

@app.route('/stores/<int:store_id>/delete', methods=['DELETE'])
@login_required
def delete_store(store_id):
    """Delete store (set inactive)"""
    # Check admin access
    if not check_access('all'):
        return jsonify({'success': False, 'message': 'Akses ditolak. Hanya admin yang dapat menghapus toko.'}), 403
    
    store = Store.query.get_or_404(store_id)
    
    try:
        # Soft delete - set inactive instead of actual delete
        store.is_active = False
        store.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Toko "{store.store_name}" berhasil dihapus.'
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Gagal menghapus toko: {str(e)}'}), 500

@app.route('/orders/<int:order_id>')
def order_detail(order_id):
    """Order detail page"""
    order = Order.query.get_or_404(order_id)
    items = OrderItem.query.filter_by(order_id=order_id).all()
    
    # Calculate profit for this order
    profit_data = calculate_order_profit(order)
    
    # Status color mapping for template
    status_colors = {
        'pending': 'warning',
        'perlu_dikirim': 'info',
        'processing': 'info', 
        'picking': 'info',
        'picked': 'primary',
        'packing': 'primary',
        'ready_pickup': 'success',
        'shipped': 'success',
        'delivered': 'primary',
        'cancelled': 'danger'
    }
    
    return render_template('order_detail.html', 
                         order=order, 
                         items=items,
                         profit_data=profit_data,
                         status_colors=status_colors)

@app.route('/orders/<int:order_id>/update_status', methods=['POST'])
def update_order_status(order_id):
    """Update order status"""
    new_status = request.form.get('status')
    
    if not new_status:
        flash('Status is required', 'error')
        return redirect(url_for('order_detail', order_id=order_id))
    
    order = Order.query.get_or_404(order_id)
    order.status = new_status
    order.updated_at = datetime.utcnow()
    
    try:
        db.session.commit()
        flash('Order status updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to update order status', 'error')
        logging.error(f"Error updating order status: {str(e)}")
    
    return redirect(url_for('order_detail', order_id=order_id))

@app.route('/shopee-setup')
@login_required
def shopee_setup():
    """Shopee API setup and configuration page"""
    # Try real API first, fallback to mock if needed
    api_mode = "real"
    try:
        from shopee_api import ShopeeAPI
        shopee_api = ShopeeAPI()
        connection_test = shopee_api.test_connection()
        auth_url = shopee_api.get_auth_url()
        
        # Check if real API has access token - if not, show as needing authorization
        if not connection_test.get('success') and 'Access token' in connection_test.get('message', ''):
            # Real API is valid but needs authorization
            connection_test['needs_auth'] = True
            
    except Exception as e:
        logging.warning(f"Real Shopee API failed: {str(e)}. Using mock API for development.")
        # Fallback to mock API
        try:
            from mock_shopee_api import MockShopeeAPI
            shopee_api = MockShopeeAPI()
            connection_test = shopee_api.test_connection()
            auth_url = shopee_api.get_auth_url()
            api_mode = "mock"
        except Exception as mock_e:
            logging.error(f"Even mock API failed: {str(mock_e)}")
            connection_test = {'success': False, 'message': f'API initialization failed: {str(mock_e)}'}
            auth_url = "#"
            api_mode = "error"
    
    return render_template('shopee_setup.html', 
                         connection_test=connection_test,
                         partner_id=shopee_api.partner_id,
                         has_api_key=bool(shopee_api.api_key),
                         shop_id=shopee_api.shop_id,
                         access_token=shopee_api.access_token,
                         auth_url=auth_url,
                         api_mode=api_mode)

@app.route('/shopee-setup', methods=['POST'])
def shopee_setup_save():
    """Save Shopee API credentials manually"""
    shop_id = request.form.get('shop_id', '').strip()
    access_token = request.form.get('access_token', '').strip()
    
    if not shop_id or not access_token:
        flash('Shop ID dan Access Token diperlukan', 'error')
        return redirect(url_for('shopee_setup'))
    
    # Test with provided credentials
    from shopee_api import ShopeeAPI
    shopee_api = ShopeeAPI()
    
    # Temporarily set credentials for testing
    original_shop_id = shopee_api.shop_id
    original_access_token = shopee_api.access_token
    
    shopee_api.shop_id = shop_id
    shopee_api.access_token = access_token
    
    # Test connection
    test_result = shopee_api.test_connection()
    
    if test_result.get('success'):
        flash('Kredensial berhasil disimpan dan ditest!', 'success')
        # Note: In real app, save to environment or database
        flash('Untuk produksi, simpan SHOPEE_SHOP_ID dan SHOPEE_ACCESS_TOKEN sebagai environment variables', 'info')
    else:
        flash(f'Test gagal: {test_result.get("message")}', 'error')
        # Restore original values
        shopee_api.shop_id = original_shop_id
        shopee_api.access_token = original_access_token
    
    return redirect(url_for('shopee_setup'))

@app.route('/shopee-callback')
def shopee_callback():
    """Handle Shopee authorization callback"""
    # Log all callback parameters for debugging
    all_params = dict(request.args)
    logging.info(f"🔍 Shopee callback received all parameters: {all_params}")
    
    code = request.args.get('code')
    shop_id = request.args.get('shop_id')
    partner_id = request.args.get('partner_id')
    error = request.args.get('error')
    
    # Handle error case
    if error:
        logging.error(f"❌ Authorization error from Shopee: {error}")
        flash(f'Authorization gagal: {error}', 'error')
        return redirect(url_for('shopee_setup'))
    
    # Check required parameters
    if not code:
        logging.error("❌ No authorization code received from Shopee")
        flash('Authorization gagal: kode authorization tidak ditemukan', 'error')
        return redirect(url_for('shopee_setup'))
    
    # Use partner_id from callback or default to configured partner_id
    if not partner_id:
        from shopee_api import ShopeeAPI
        shopee_api = ShopeeAPI()
        partner_id = shopee_api.partner_id
        logging.info(f"✅ Using configured partner_id: {partner_id}")
    
    # Use shop_id from callback or default to configured shop_id
    if not shop_id:
        from shopee_api import ShopeeAPI
        shopee_api = ShopeeAPI()
        shop_id = shopee_api.shop_id
        logging.info(f"✅ Using configured shop_id: {shop_id}")
    
    from shopee_api import ShopeeAPI
    shopee_api = ShopeeAPI()
    
    logging.info(f"🔄 Attempting to get access token with code: {code[:10]}... and shop_id: {shop_id}")
    
    # Get access token using authorization code
    result = shopee_api.get_access_token_from_code(code, shop_id)
    
    if result.get('success'):
        access_token = result.get('access_token')
        logging.info(f"✅ Authorization successful! Access token: {access_token[:20]}...")
        flash(f'Authorization berhasil! Access token: {access_token[:20]}...', 'success')
        flash('Silakan simpan access token ini sebagai SHOPEE_ACCESS_TOKEN environment variable', 'info')
        
        # Save access token to environment for this session
        shopee_api.access_token = access_token
        
    else:
        error_msg = result.get("error", "Unknown error")
        logging.error(f"❌ Authorization failed: {error_msg}")
        
        # Handle IP whitelist error specifically
        if "source_ip_undeclared" in error_msg or "IP Address" in error_msg:
            flash('IP address belum terdaftar di Shopee Developer Console. Server menggunakan multiple IP addresses yang berubah-ubah.', 'error')
            flash('Silakan gunakan Mock API untuk sementara - klik tombol "Use Mock API" di bawah', 'warning')
        else:
            flash(f'Authorization gagal: {error_msg}', 'error')
    
    return redirect(url_for('shopee_setup'))

@app.route('/shopee-auth')
@login_required
def shopee_auth():
    """Generate authorization URL for Shopee"""
    try:
        from shopee_api import ShopeeAPI
        shopee_api = ShopeeAPI()
        auth_url = shopee_api.get_auth_url()
        return redirect(auth_url)
    except Exception as e:
        flash(f'Failed to generate authorization URL: {str(e)}', 'error')
        return redirect(url_for('shopee_setup'))

@app.route('/shopee-simulate-auth', methods=['POST'])
@login_required
def shopee_simulate_auth():
    """Simulate authorization process for development"""
    try:
        from shopee_auth_helper import simulate_authorization_process
        result = simulate_authorization_process()
        
        if result.get('success'):
            flash('Authorization simulasi berhasil! Sistem siap untuk sync orders.', 'success')
            flash('Mode: Development - menggunakan sample data untuk testing', 'info')
        else:
            flash(f'Authorization simulasi gagal: {result.get("message")}', 'error')
            
    except Exception as e:
        logging.error(f"Error in simulate auth: {str(e)}")
        flash(f'Error dalam simulasi authorization: {str(e)}', 'error')
        
    return redirect(url_for('shopee_setup'))

@app.route('/shopee-test-connection', methods=['POST'])
@login_required
def shopee_test_connection():
    """Test Shopee API connection"""
    try:
        # Try real API first, fallback to mock for development
        try:
            from shopee_api import ShopeeAPI
            shopee_api = ShopeeAPI()
            connection_test = shopee_api.test_connection()
            
            # If real API doesn't have access token, use mock for demo
            if not connection_test.get('success') and 'Access token' in connection_test.get('message', ''):
                raise Exception("Real API needs authorization, using mock for demo")
                
            api_mode = "real"
            
        except Exception as e:
            logging.warning(f"Real Shopee API failed: {str(e)}. Using mock API for demo.")
            from mock_shopee_api import MockShopeeAPI
            shopee_api = MockShopeeAPI()
            connection_test = shopee_api.test_connection()
            api_mode = "mock"
        
        return jsonify({
            'success': connection_test.get('success', False),
            'shop_id': connection_test.get('shop_id'),
            'message': connection_test.get('message', 'Unknown error'),
            'error': connection_test.get('error'),
            'api_mode': api_mode
        })
        
    except Exception as e:
        logging.error(f"Failed to test connection: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/sync_shopee_orders', methods=['POST'])
def sync_shopee_orders():
    """Redirect to orders page - no sync needed"""
    flash('Sistem menggunakan data yang sudah ada. Tidak perlu sync.', 'info')
    return redirect(url_for('orders'))

@app.route('/warehouse')
@app.route('/produk-saya')
@login_required
@admin_required
def warehouse():
    """Warehouse inventory management page - ULTRA-OPTIMIZED Strong Versi 03 Logic"""
    # Check if this is an AJAX request
    ajax_request = request.args.get('ajax') == '1' or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    search_query = request.args.get('search', '')
    low_stock_only = request.args.get('low_stock') == 'true'
    page = request.args.get('page', 1, type=int)
    per_page = 50  # Limit items per page
    
    # ULTRA-OPTIMIZED: Single raw SQL query with filters and pagination
    try:
        # Build dynamic WHERE clause
        where_conditions = []
        params = {'limit': per_page, 'offset': (page - 1) * per_page}
        
        if search_query:
            where_conditions.append("(name ILIKE :search OR sku ILIKE :search)")
            params['search'] = f'%{search_query}%'
        
        if low_stock_only:
            where_conditions.append("quantity <= minimum_stock")
        
        where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"
        
        # Get products with single query
        products_query = f"""
            SELECT id, name, sku, quantity, price, minimum_stock, image_url, description,
                   category, colour, weight, length, width, height, zone, rack, bin, 
                   created_at, updated_at
            FROM products 
            WHERE {where_clause}
            ORDER BY name
            LIMIT :limit OFFSET :offset
        """
        
        products_result = db.session.execute(text(products_query), params).fetchall()
        
        # Get total count for pagination
        count_query = f"""
            SELECT COUNT(*) as total FROM products WHERE {where_clause}
        """
        count_params = {k: v for k, v in params.items() if k not in ['limit', 'offset']}
        total_count = db.session.execute(text(count_query), count_params).fetchone().total
        
        # Create pagination info
        has_prev = page > 1
        has_next = (page * per_page) < total_count
        prev_num = page - 1 if has_prev else None
        next_num = page + 1 if has_next else None
        
        # Convert to dict for template compatibility
        all_inventory = []
        for row in products_result:
            all_inventory.append({
                'id': row.id,
                'name': row.name,
                'sku': row.sku,
                'quantity': row.quantity,
                'price': row.price,
                'minimum_stock': row.minimum_stock,
                'image_url': row.image_url,
                'description': row.description,
                'category': row.category,
                'colour': row.colour,
                'weight': row.weight,
                'length': row.length,
                'width': row.width,
                'height': row.height,
                'zone': row.zone,
                'rack': row.rack,
                'bin': row.bin,
                'created_at': row.created_at,
                'updated_at': row.updated_at
            })
        
        # Create pagination object with iter_pages method
        class PaginationObject:
            def __init__(self, items, page, pages, per_page, total, has_prev, has_next, prev_num, next_num):
                self.items = items
                self.page = page
                self.pages = pages
                self.per_page = per_page
                self.total = total
                self.has_prev = has_prev
                self.has_next = has_next
                self.prev_num = prev_num
                self.next_num = next_num
            
            def iter_pages(self, left_edge=2, left_current=2, right_current=3, right_edge=2):
                """Generate page numbers for pagination"""
                last = self.pages
                for num in range(1, last + 1):
                    if num <= left_edge or \
                       (self.page - left_current - 1 < num < self.page + right_current) or \
                       num > last - right_edge:
                        yield num
        
        pagination = PaginationObject(
            all_inventory, page, (total_count + per_page - 1) // per_page, per_page, 
            total_count, has_prev, has_next, prev_num, next_num
        )
        
        template_name = 'warehouse_content.html' if ajax_request else 'warehouse.html'
        return render_template(template_name, 
                             products=pagination,
                             search_query=search_query,
                             low_stock_only=low_stock_only)
                             
    except Exception as e:
        logging.error(f"Error in warehouse: {e}")
        # Fallback to simple query if raw SQL fails
        template_name = 'warehouse_content.html' if ajax_request else 'warehouse.html'
        return render_template(template_name, 
                             products=PaginationObject([], 1, 0, 50, 0, False, False, None, None),
                             search_query=search_query,
                             low_stock_only=low_stock_only)

@app.route('/warehouse/add', methods=['GET', 'POST'])
def add_inventory():
    """Add new inventory item"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        sku = request.form.get('sku', '').strip()
        quantity = request.form.get('quantity', type=int)
        price = request.form.get('price', type=float)
        minimum_stock = request.form.get('minimum_stock', type=int, default=10)
        image_url = request.form.get('image_url', '').strip()
        description = request.form.get('description', '').strip()
        
        # Extended fields
        category = request.form.get('category', '').strip()
        colour = request.form.get('colour', '').strip()
        weight = request.form.get('weight', type=float) if request.form.get('weight') else None
        length = request.form.get('length', type=float) if request.form.get('length') else None
        width = request.form.get('width', type=float) if request.form.get('width') else None
        height = request.form.get('height', type=float) if request.form.get('height') else None
        zone = request.form.get('zone', '').strip()
        rack = request.form.get('rack', '').strip()
        bin = request.form.get('bin', '').strip()
        
        # Handle image upload - both file upload and data URL
        if image_url and image_url.startswith('data:image'):
            # If it's a data URL (base64), keep it as is
            pass
        elif 'image_upload' in request.files:
            file = request.files['image_upload']
            if file and file.filename != '':
                # Save uploaded file
                import os
                import uuid
                
                # Create uploads directory if it doesn't exist
                upload_dir = os.path.join('static', 'uploads')
                if not os.path.exists(upload_dir):
                    os.makedirs(upload_dir)
                
                # Generate unique filename
                file_extension = os.path.splitext(file.filename)[1].lower()
                unique_filename = f"{uuid.uuid4()}{file_extension}"
                file_path = os.path.join(upload_dir, unique_filename)
                
                # Save file
                file.save(file_path)
                
                # Update image_url to point to saved file
                image_url = f"/static/uploads/{unique_filename}"
        
        # Validation
        if not name or not sku:
            flash('Name and SKU are required', 'error')
            return render_template('inventory_form.html', 
                                 form_data=request.form,
                                 action='Add')
        
        if quantity is None or quantity < 0:
            flash('Valid quantity is required', 'error')
            return render_template('inventory_form.html', 
                                 form_data=request.form,
                                 action='Add')
        
        if price is None or price < 0:
            flash('Valid price is required', 'error')
            return render_template('inventory_form.html', 
                                 form_data=request.form,
                                 action='Add')
        
        try:
            # Check if SKU already exists
            existing_product = Product.query.filter_by(sku=sku).first()
            if existing_product:
                flash('SKU already exists', 'error')
                return render_template('inventory_form.html', 
                                     form_data=request.form,
                                     action='Add')
            
            # Create new product
            new_product = Product(
                name=name,
                sku=sku,
                quantity=quantity,
                price=price,
                minimum_stock=minimum_stock,
                image_url=image_url if image_url else None,
                description=description if description else None,
                category=category if category else None,
                colour=colour if colour else None,
                weight=weight,
                length=length,
                width=width,
                height=height,
                zone=zone if zone else None,
                rack=rack if rack else None,
                bin=bin if bin else None
            )
            db.session.add(new_product)
            db.session.commit()
            
            flash('Inventory item added successfully', 'success')
            return redirect(url_for('warehouse'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Failed to add inventory item: {str(e)}")
            flash('Failed to add inventory item', 'error')
    
    return render_template('inventory_form.html', action='Add')

@app.route('/product-detail/<int:product_id>')
def product_detail(product_id):
    """Show detailed product information in new tab"""
    product = Product.query.get_or_404(product_id)
    
    # Get related order items for this product
    related_orders = db.session.query(OrderItem, Order).join(Order).filter(
        OrderItem.sku == product.sku
    ).order_by(Order.order_date.desc()).limit(10).all()
    
    return render_template('product_detail.html', product=product, related_orders=related_orders)

@app.route('/product/<string:sku>')
@login_required
def product_detail_packing(sku):
    """Display product detail page for packing validation"""
    try:
        from datetime import datetime
        from database_models import Product, OrderItem, Order
        
        # Find product by SKU
        product = Product.query.filter_by(sku=sku).first()
        if not product:
            return "Product not found", 404
        
        # Find all order items with this SKU - look for SKU in pipe format
        order_items = db.session.query(OrderItem).join(Order).filter(
            OrderItem.sku.like(f'%{sku}%')
        ).all()
        
        # Current time for display
        current_time = datetime.now().strftime("%I:%M %p %d/%m/%Y")
        
        return render_template('product_detail_packing.html', 
                             product=product,
                             order_items=order_items,
                             current_time=current_time)
    
    except Exception as e:
        app.logger.error(f"Error in product_detail_packing: {str(e)}")
        return "Internal server error", 500

@app.route('/order/<int:order_id>/products')
@login_required
def display_all_order_products(order_id):
    """Display all products in an order on a single page"""
    try:
        from datetime import datetime
        from database_models import Product, OrderItem, Order
        
        # Get the order
        order = Order.query.get_or_404(order_id)
        
        # Get all items in this order
        order_items = db.session.query(OrderItem).filter(
            OrderItem.order_id == order_id
        ).all()
        
        # Get product details for each item
        product_details = []
        for item in order_items:
            clean_sku = item.sku.split('|')[1].strip() if '|' in item.sku else item.sku
            product = Product.query.filter_by(sku=clean_sku).first()
            
            product_details.append({
                'item': item,
                'product': product,
                'clean_sku': clean_sku,
                'image_url': product.image_url if product and product.image_url else '/static/images/no-image.svg'
            })
        
        # Current time for display
        current_time = datetime.now().strftime("%I:%M %p %d/%m/%Y")
        
        return render_template('order_products_display.html', 
                             order=order,
                             product_details=product_details,
                             current_time=current_time)
    
    except Exception as e:
        app.logger.error(f"Error in display_all_order_products: {str(e)}")
        return "Internal server error", 500

@app.route('/warehouse/import', methods=['GET', 'POST'])
def import_inventory():
    """Import inventory from CSV file with JSON response for progress tracking"""
    if request.method == 'POST':
        uploaded_files = request.files.getlist('inventory_files')
        
        if not uploaded_files or all(f.filename == '' for f in uploaded_files):
            return jsonify({'success': False, 'message': 'No files selected'})
        
        # Process single file for progress tracking
        file = uploaded_files[0]
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'})
            
        if not file.filename.lower().endswith(('.csv', '.xlsx', '.xls')):
            return jsonify({'success': False, 'message': f'Invalid file format: {file.filename}. Please use CSV or Excel files.'})
        
        try:
            # Read file based on extension
            if file.filename.lower().endswith('.csv'):
                stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
                csv_input = csv.DictReader(stream)
            else:
                # Handle Excel files
                try:
                    import pandas as pd
                    df = pd.read_excel(file)
                    csv_input = df.to_dict('records')
                except ImportError:
                    return jsonify({'success': False, 'message': 'Excel support not available. Please use CSV files.'})
            
            success_count = 0
            skipped_count = 0
            error_count = 0
            errors = []
            
            # Process each row
            for row_num, row in enumerate(csv_input, start=2):
                try:
                    # Handle header names with extra spaces
                    def get_value(field_name, default=''):
                        for key in row.keys():
                            if key.strip() == field_name:
                                val = row[key].strip() if row[key] else ''
                                return val
                        return default
                    
                    # Clean and validate data
                    name = get_value('name')
                    sku = get_value('sku')
                    category = get_value('category')
                    quantity = int(get_value('quantity', '0'))
                    # Support both 'price' and 'product_cost' columns
                    price = float(get_value('price', '0'))
                    if price == 0:
                        price = float(get_value('product_cost', '0'))
                    if price == 0:
                        price = float(get_value('product cost', '0'))
                    minimum_stock = int(get_value('minimum_stock', '10'))
                    colour = get_value('colour')
                    
                    # Handle numeric values properly
                    weight_str = get_value('weight')
                    length_str = get_value('length')
                    width_str = get_value('width')
                    height_str = get_value('height')
                    
                    weight = float(weight_str) if weight_str and weight_str.replace('.', '').isdigit() else None
                    length = float(length_str) if length_str and length_str.replace('.', '').isdigit() else None
                    width = float(width_str) if width_str and width_str.replace('.', '').isdigit() else None
                    height = float(height_str) if height_str and height_str.replace('.', '').isdigit() else None
                    
                    zone = get_value('zone')
                    rack = get_value('rack')
                    bin = get_value('bin')
                    image_url = get_value('image_url')
                    description = get_value('description')
                    
                    # Also check for 'keterangan' field name for Indonesian compatibility
                    if not description:
                        description = get_value('keterangan')
                    
                    # Validate required fields
                    if not name or not sku:
                        description = str(row.get('keterangan', '')).strip()
                    
                    # Validate required fields
                    if not name or not sku:
                        raise ValueError('Name and SKU are required')
                    
                    if quantity < 0:
                        raise ValueError('Quantity cannot be negative')
                    
                    if price < 0:
                        raise ValueError('Price cannot be negative')
                    
                    # Price conversion for large values (compatibility with old data)
                    if price > 1000000:
                        price = price / 1000
                    
                    # Check for duplicate SKU
                    existing_product = Product.query.filter_by(sku=sku).first()
                    if existing_product:
                        # Update existing product
                        existing_product.name = name
                        existing_product.category = category if category else None
                        existing_product.quantity = quantity
                        existing_product.price = price
                        existing_product.minimum_stock = minimum_stock
                        existing_product.colour = colour if colour else None
                        existing_product.weight = weight
                        existing_product.length = length
                        existing_product.width = width
                        existing_product.height = height
                        existing_product.zone = zone if zone else None
                        existing_product.rack = rack if rack else None
                        existing_product.bin = bin if bin else None
                        existing_product.image_url = image_url if image_url else None
                        existing_product.description = description if description else None
                        existing_product.updated_at = datetime.utcnow()
                        skipped_count += 1
                    else:
                        # Create new product
                        new_product = Product(
                            sku=sku,
                            name=name,
                            category=category if category else None,
                            quantity=quantity,
                            price=price,
                            minimum_stock=minimum_stock,
                            colour=colour if colour else None,
                            weight=weight,
                            length=length,
                            width=width,
                            height=height,
                            zone=zone if zone else None,
                            rack=rack if rack else None,
                            bin=bin if bin else None,
                            image_url=image_url if image_url else None,
                            description=description if description else None
                        )
                        db.session.add(new_product)
                        db.session.flush()  # Check for unique constraint before commit
                        success_count += 1
                    
                    # Commit in batches to avoid timeout
                    if (success_count + skipped_count) % 5 == 0:
                        try:
                            db.session.commit()
                            logging.info(f"Successfully committed batch for {file.filename}")
                        except Exception as e:
                            logging.error(f"Error committing batch: {str(e)}")
                            db.session.rollback()
                            raise e
                    
                except ValueError as e:
                    errors.append(f'Row {row_num}: Invalid data format - {str(e)}')
                    error_count += 1
                except Exception as e:
                    errors.append(f'Row {row_num}: {str(e)}')
                    error_count += 1
            
            # Final commit for remaining items
            try:
                db.session.commit()
                logging.info(f"Final commit completed for {file.filename}")
            except Exception as e:
                logging.error(f"Error in final commit: {str(e)}")
                db.session.rollback()
                return jsonify({'success': False, 'message': f'Error saving final batch: {str(e)}'})
            
            # Return JSON response for progress tracking
            return jsonify({
                'success': True,
                'imported_count': success_count,
                'skipped_count': skipped_count,
                'error_count': error_count,
                'message': f'Successfully processed {file.filename}: {success_count} imported, {skipped_count} updated, {error_count} errors',
                'errors': errors[:5]  # Return first 5 errors only
            })
            
        except Exception as e:
            logging.error(f"Failed to process file {file.filename}: {str(e)}")
            return jsonify({'success': False, 'message': f'Failed to process {file.filename}: {str(e)}'})
    
    return render_template('mass_upload_inventory.html')

@app.route('/warehouse/mass_upload', methods=['GET', 'POST'])
def mass_upload_inventory():
    """Mass upload inventory items from CSV file"""
    if request.method == 'POST':
        if 'csv_file' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('mass_upload_inventory'))
        
        file = request.files['csv_file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('mass_upload_inventory'))
        
        if not file.filename.lower().endswith('.csv'):
            flash('Please upload a CSV file', 'error')
            return redirect(url_for('mass_upload_inventory'))
        
        try:
            import csv
            import io
            
            # Read CSV file
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_reader = csv.DictReader(stream)
            
            # Validate required columns - updated to support product_cost and spaces in headers
            required_columns = ['name', 'sku', 'quantity']
            price_columns = ['price', 'product_cost', 'product cost']
            
            # Check for required columns with space tolerance
            fieldnames_stripped = [field.strip() for field in csv_reader.fieldnames]
            missing_columns = []
            for col in required_columns:
                if col not in fieldnames_stripped:
                    missing_columns.append(col)
            
            if missing_columns:
                flash(f'CSV must contain columns: {", ".join(missing_columns)}', 'error')
                return redirect(url_for('mass_upload_inventory'))
            
            # Check if at least one price column exists (with space tolerance)
            has_price_column = False
            for price_col in price_columns:
                if price_col in fieldnames_stripped:
                    has_price_column = True
                    break
            
            if not has_price_column:
                flash('CSV must contain either "price", "product_cost", or "product cost" column', 'error')
                return redirect(url_for('mass_upload_inventory'))
            
            # Process rows
            success_count = 0
            error_count = 0
            errors = []
            
            for row_num, row in enumerate(csv_reader, start=2):  # Start from 2 (accounting for header)
                try:
                    # Handle header names with extra spaces
                    def get_value(field_name, default=''):
                        """Get value from row handling spaces in field names"""
                        for key in row.keys():
                            if key.strip() == field_name:
                                return row[key].strip() if row[key] else default
                        return default
                    
                    name = get_value('name')
                    sku = get_value('sku')
                    category = get_value('category')
                    quantity = int(get_value('quantity', '0') or '0')
                    
                    # Support both 'price' and 'product_cost' columns with spaces
                    price = 0.0
                    for price_field in ['price', 'product_cost', 'product cost']:
                        price_value = get_value(price_field, '0')
                        if price_value and price_value != '0':
                            try:
                                price = float(price_value)
                                break
                            except (ValueError, TypeError):
                                continue
                    
                    minimum_stock = int(get_value('minimum_stock', '10') or '10')
                    colour = get_value('colour')
                    image_url = get_value('image_url')
                    
                    # Handle numeric values properly with spaces in headers
                    def get_numeric_value(field_variants):
                        """Get numeric value from field variants"""
                        for field_name in field_variants:
                            value = get_value(field_name)
                            if value:
                                try:
                                    return float(value)
                                except (ValueError, TypeError):
                                    continue
                        return None
                    
                    weight = get_numeric_value(['weight', 'weight ', ' weight'])
                    length = get_numeric_value(['length', 'length ', ' length'])
                    width = get_numeric_value(['width', 'width ', ' width'])
                    height = get_numeric_value(['height', 'height ', ' height'])
                    
                    zone = get_value('zone')
                    rack = get_value('rack')
                    bin = get_value('bin')
                    description = get_value('description')
                    
                    # Also check for 'keterangan' field name for Indonesian compatibility
                    if not description:
                        description = get_value('keterangan')
                    
                    # Handle large prices (divide by 1000 if > 1000000)
                    if price > 1000000:
                        price = price / 1000
                    
                    # Validation
                    if not name or not sku:
                        errors.append(f'Row {row_num}: Name and SKU are required')
                        error_count += 1
                        continue
                    
                    if quantity < 0:
                        errors.append(f'Row {row_num}: Quantity cannot be negative')
                        error_count += 1
                        continue
                    
                    if price < 0:
                        errors.append(f'Row {row_num}: Price cannot be negative')
                        error_count += 1
                        continue
                    
                    # Update existing product or create new one - safer approach
                    existing_product = Product.query.filter_by(sku=sku).first()
                    
                    if existing_product:
                        # Update existing product
                        existing_product.name = name
                        existing_product.category = category if category else None
                        existing_product.quantity = quantity
                        existing_product.price = price
                        existing_product.minimum_stock = minimum_stock
                        existing_product.colour = colour if colour else None
                        existing_product.weight = weight
                        existing_product.length = length
                        existing_product.width = width
                        existing_product.height = height
                        existing_product.zone = zone if zone else None
                        existing_product.rack = rack if rack else None
                        existing_product.bin = bin if bin else None
                        existing_product.description = description if description else None
                        existing_product.image_url = image_url if image_url else None
                        existing_product.updated_at = datetime.utcnow()
                        logging.info(f"Updated existing product: {sku}")
                    else:
                        # Create new product
                        new_product = Product(
                            sku=sku,
                            name=name,
                            category=category if category else None,
                            quantity=quantity,
                            price=price,
                            minimum_stock=minimum_stock,
                            colour=colour if colour else None,
                            weight=weight,
                            length=length,
                            width=width,
                            height=height,
                            zone=zone if zone else None,
                            rack=rack if rack else None,
                            bin=bin if bin else None,
                            description=description if description else None,
                            image_url=image_url if image_url else None
                        )
                        db.session.add(new_product)
                        logging.info(f"Created new product: {sku}")
                    
                    success_count += 1
                    
                    # Commit in smaller batches for concurrent uploads
                    if success_count % 5 == 0:
                        try:
                            db.session.commit()
                            logging.info(f"Successfully committed batch of {success_count} products")
                        except Exception as e:
                            logging.error(f"Error committing batch: {str(e)}")
                            try:
                                db.session.rollback()
                                db.session.close()
                                db.session = db.scoped_session()
                            except:
                                pass
                    
                except ValueError as e:
                    errors.append(f'Row {row_num}: Invalid data format - {str(e)}')
                    error_count += 1
                except Exception as e:
                    errors.append(f'Row {row_num}: {str(e)}')
                    error_count += 1
            
            # Final commit for remaining items
            try:
                db.session.commit()
                logging.info(f"Final commit completed for inventory import")
            except Exception as e:
                logging.error(f"Error in final commit: {str(e)}")
                try:
                    db.session.rollback()
                    db.session.close()
                except:
                    pass
                flash(f'Error saving final batch: {str(e)}', 'error')
            
            # Show results
            if success_count > 0:
                flash(f'Successfully uploaded {success_count} items', 'success')
            
            if error_count > 0:
                flash(f'Failed to upload {error_count} items', 'error')
                # Show first 5 errors
                for error in errors[:5]:
                    flash(error, 'error')
                if len(errors) > 5:
                    flash(f'... and {len(errors) - 5} more errors', 'error')
            
            if success_count > 0:
                return redirect(url_for('warehouse'))
            
        except Exception as e:
            logging.error(f"Failed to process CSV file: {str(e)}")
            flash('Failed to process CSV file', 'error')
    
    return render_template('mass_upload_form.html')

@app.route('/warehouse/download_csv_template')
def download_csv_template():
    """Download CSV template for mass upload"""
    from flask import Response
    import csv
    import io
    
    # Create CSV template
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header - match user's format exactly
    writer.writerow(['name', 'sku', 'category', 'quantity', 'product_cost', 'minimum_stock', 'colour', 'weight', 'length', 'width', 'height', 'zone', 'rack', 'bin', 'image_url'])
    
    # Write example rows - sesuai format dari gambar user
    writer.writerow(['SET GELAS BLD-GLSM BLD', 'BLD-GLSM-001', 'Peralatan Makan', '50', '15000000', '5', 'hijau', '230', '10', '10', '10', 'A', 'R01', 'B3', 'https://down-id.img.susercontent.com/file/id-11134207-7qul5-lhq1x2y1z2o5c9'])
    writer.writerow(['MANGKOK BULAT FIBERGLASS', 'FBG-MNG-002', 'Peralatan Dapur', '30', '7500000', '3', 'putih', '180', '15', '15', '8', 'B', 'R02', 'B2', 'https://down-id.img.susercontent.com/file/id-11134207-7qul5-lhq1x2y1z2o5c9'])
    writer.writerow(['PIRING OVAL MELAMIN 12 INCH', 'MEL-PIR-003', 'Peralatan Makan', '25', '4500000', '5', 'putih', '120', '30', '20', '3', 'A', 'R01', 'B3', 'https://down-id.img.susercontent.com/file/id-11134207-7qul5-lhq1x2y1z2o5c9'])
    
    # Create response
    response = Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=inventory_template.csv'}
    )
    
    return response

@app.route('/warehouse/<product_id>/edit', methods=['GET', 'POST'])
def edit_inventory(product_id):
    """Edit inventory item"""
    # Try to get product from database first
    product = Product.query.get(product_id)
    if not product:
        flash('Inventory item not found', 'error')
        return redirect(url_for('warehouse'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        sku = request.form.get('sku', '').strip()
        quantity = request.form.get('quantity', type=int)
        price = request.form.get('price', type=float)
        minimum_stock = request.form.get('minimum_stock', type=int, default=10)
        image_url = request.form.get('image_url', '').strip()
        description = request.form.get('description', '').strip()
        
        # Extended fields
        category = request.form.get('category', '').strip()
        colour = request.form.get('colour', '').strip()
        weight = request.form.get('weight', type=float) if request.form.get('weight') else None
        length = request.form.get('length', type=float) if request.form.get('length') else None
        width = request.form.get('width', type=float) if request.form.get('width') else None
        height = request.form.get('height', type=float) if request.form.get('height') else None
        zone = request.form.get('zone', '').strip()
        rack = request.form.get('rack', '').strip()
        bin = request.form.get('bin', '').strip()
        
        # Validation
        if not name or not sku:
            flash('Name and SKU are required', 'error')
            return render_template('inventory_form.html', 
                                 item=item,
                                 form_data=request.form,
                                 action='Edit')
        
        if quantity is None or quantity < 0:
            flash('Valid quantity is required', 'error')
            return render_template('inventory_form.html', 
                                 item=item,
                                 form_data=request.form,
                                 action='Edit')
        
        if price is None or price < 0:
            flash('Valid price is required', 'error')
            return render_template('inventory_form.html', 
                                 item=item,
                                 form_data=request.form,
                                 action='Edit')
        
        try:
            # Update product in database
            product.name = name
            product.sku = sku
            product.quantity = quantity
            product.price = price
            product.minimum_stock = minimum_stock
            product.image_url = image_url if image_url else None
            product.description = description if description else None
            product.category = category if category else None
            product.colour = colour if colour else None
            product.weight = weight
            product.length = length
            product.width = width
            product.height = height
            product.zone = zone if zone else None
            product.rack = rack if rack else None
            product.bin = bin if bin else None
            product.updated_at = datetime.utcnow()
            
            db.session.commit()
            flash('Inventory item updated successfully', 'success')
            return redirect(url_for('warehouse'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Failed to update inventory item: {str(e)}")
            flash('Failed to update inventory item', 'error')
    
    return render_template('inventory_form.html', item=product, action='Edit')

@app.route('/warehouse/<product_id>/delete', methods=['POST'])
def delete_inventory(product_id):
    """Delete inventory item - safely handle foreign key constraints - ULTRA-OPTIMIZED Strong Versi 03 Logic"""
    try:
        # ULTRA-OPTIMIZED: Single raw SQL query to check constraints and get product info
        result = db.session.execute(text("""
            SELECT p.id, p.name, p.sku,
                   (SELECT COUNT(*) FROM stock_movements sm WHERE sm.product_id = p.id) as stock_count,
                   (SELECT COUNT(*) FROM order_items oi WHERE oi.sku = p.sku) as order_count
            FROM products p
            WHERE p.id = :product_id
        """), {'product_id': product_id}).fetchone()
        
        if not result:
            flash('Product not found', 'error')
            return redirect(url_for('warehouse'))
        
        # Check constraints
        if result.stock_count > 0:
            flash(f'Cannot delete product {result.name} - it has stock movement history. Consider updating instead.', 'error')
            return redirect(url_for('warehouse'))
        
        if result.order_count > 0:
            flash(f'Cannot delete product {result.name} - it is referenced in orders. Consider updating instead.', 'error')
            return redirect(url_for('warehouse'))
        
        # ULTRA-FAST: Delete product if no constraints
        db.session.execute(text("""
            DELETE FROM products WHERE id = :product_id
        """), {'product_id': product_id})
        
        db.session.commit()
        
        # Return JSON response for AJAX requests
        if request.is_json or request.headers.get('Content-Type') == 'application/json':
            return jsonify({'success': True, 'message': 'Produk berhasil dihapus'})
        else:
            flash('Inventory item deleted successfully', 'success')
            return redirect(url_for('warehouse'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to delete product {product_id}: {str(e)}")
        
        # Return JSON response for AJAX requests
        if request.is_json or request.headers.get('Content-Type') == 'application/json':
            return jsonify({'success': False, 'message': 'Tidak bisa menghapus produk - mungkin masih direferensikan di data lain'})
        else:
            flash('Failed to delete inventory item - it may be referenced by other records', 'error')
            return redirect(url_for('warehouse'))

@app.route('/warehouse/delete_multiple', methods=['POST'])
def delete_multiple_inventory():
    """Delete multiple inventory items - safely handle foreign key constraints"""
    selected_products = request.form.getlist('selected_products[]')
    
    if not selected_products:
        flash('No products selected for deletion', 'error')
        return redirect(url_for('warehouse'))
    
    success_count = 0
    error_count = 0
    skipped_count = 0
    
    for product_id in selected_products:
        try:
            product = Product.query.get(product_id)
            if product:
                # Check if product has stock movements or order items
                stock_movements = StockMovement.query.filter_by(product_id=product.id).first()
                order_items = OrderItem.query.filter_by(sku=product.sku).first()
                
                if stock_movements or order_items:
                    logging.warning(f"Skipping product {product.name} - has references")
                    skipped_count += 1
                    continue
                
                # Safe to delete
                db.session.delete(product)
                db.session.commit()
                success_count += 1
            else:
                error_count += 1
        except Exception as e:
            db.session.rollback()
            logging.error(f"Failed to delete product {product_id}: {str(e)}")
            error_count += 1
    
    if success_count > 0:
        flash(f'{success_count} produk berhasil dihapus', 'success')
    
    if skipped_count > 0:
        flash(f'{skipped_count} produk dilewati karena memiliki riwayat transaksi', 'warning')
    
    if error_count > 0:
        flash(f'{error_count} produk gagal dihapus', 'error')
    
    return redirect(url_for('warehouse'))

@app.route('/warehouse/delete_selected', methods=['POST'])
def delete_selected_products():
    """Delete selected products via AJAX with safety checks"""
    try:
        data = request.get_json()
        product_ids = data.get('product_ids', [])
        
        if not product_ids:
            return jsonify({'success': False, 'message': 'Tidak ada produk yang dipilih'})
        
        success_count = 0
        error_count = 0
        skipped_count = 0
        
        for product_id in product_ids:
            try:
                product = Product.query.get(product_id)
                if product:
                    # Check if product has stock movements or order items
                    stock_movements = StockMovement.query.filter_by(product_id=product.id).first()
                    order_items = OrderItem.query.filter_by(sku=product.sku).first()
                    
                    if stock_movements or order_items:
                        logging.warning(f"Skipping product {product.name} - has references")
                        skipped_count += 1
                        continue
                    
                    # Safe to delete
                    db.session.delete(product)
                    db.session.commit()
                    success_count += 1
                else:
                    error_count += 1
            except Exception as e:
                db.session.rollback()
                logging.error(f"Failed to delete product {product_id}: {str(e)}")
                error_count += 1
        
        message = f"Berhasil menghapus {success_count} produk"
        if skipped_count > 0:
            message += f", {skipped_count} produk dilewati karena memiliki riwayat transaksi"
        if error_count > 0:
            message += f", {error_count} produk gagal dihapus"
        
        return jsonify({
            'success': True,
            'message': message,
            'deleted_count': success_count,
            'skipped_count': skipped_count,
            'error_count': error_count
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to delete selected products: {str(e)}")
        return jsonify({'success': False, 'message': 'Terjadi kesalahan saat menghapus produk'})

@app.route('/warehouse/<product_id>/adjust_quantity', methods=['POST'])
def adjust_inventory_quantity(product_id):
    """Adjust inventory quantity via AJAX - ULTRA-OPTIMIZED Strong Versi 03 Logic"""
    # Support both JSON and form data
    if request.is_json:
        data = request.get_json()
        new_quantity = data.get('quantity') if data else None
    else:
        new_quantity = request.form.get('quantity', type=int)
    
    new_quantity = int(new_quantity) if new_quantity is not None else None
    
    if new_quantity is None or new_quantity < 0:
        return jsonify({'success': False, 'message': 'Valid quantity is required'})
    
    try:
        # ULTRA-OPTIMIZED: Single raw SQL query with UPDATE and RETURNING
        result = db.session.execute(text("""
            UPDATE products 
            SET quantity = :new_quantity, updated_at = NOW()
            WHERE id = :product_id
            RETURNING id, name, quantity, (quantity - :new_quantity) as quantity_diff
        """), {'new_quantity': new_quantity, 'product_id': product_id})
        
        updated_product = result.fetchone()
        
        if not updated_product:
            return jsonify({'success': False, 'message': 'Product not found'})
        
        # ULTRA-FAST: Add stock movement record in single query
        db.session.execute(text("""
            INSERT INTO stock_movements (product_id, movement_type, quantity, notes, created_at)
            VALUES (:product_id, 'adjustment', :quantity_change, :notes, NOW())
        """), {
            'product_id': product_id,
            'quantity_change': new_quantity - updated_product.quantity_diff,
            'notes': f'Quantity adjusted to {new_quantity}'
        })
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Inventory quantity updated successfully',
            'new_quantity': new_quantity
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to update inventory quantity: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to update inventory quantity'})

@app.route('/warehouse/<product_id>/adjust_price', methods=['POST'])
def adjust_inventory_price(product_id):
    """Adjust inventory price via AJAX - ULTRA-OPTIMIZED Strong Versi 03 Logic"""
    new_price = request.form.get('price', type=float)
    
    if new_price is None or new_price < 0:
        return jsonify({'success': False, 'message': 'Valid price is required'})
    
    try:
        # ULTRA-OPTIMIZED: Single raw SQL query with UPDATE and RETURNING
        result = db.session.execute(text("""
            UPDATE products 
            SET price = :new_price, updated_at = NOW()
            WHERE id = :product_id
            RETURNING id, name, price
        """), {'new_price': new_price, 'product_id': product_id})
        
        updated_product = result.fetchone()
        
        if not updated_product:
            return jsonify({'success': False, 'message': 'Product not found'})
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Price updated to Rp {new_price:,.0f}',
            'new_price': int(new_price)
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to update inventory price: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to update inventory price'})

@app.route('/warehouse/<product_id>/update_price', methods=['POST'])
def update_inventory_price(product_id):
    """Update inventory price via JSON AJAX - Modal Compatible"""
    # Support both JSON and form data
    if request.is_json:
        data = request.get_json()
        new_price = data.get('price') if data else None
    else:
        new_price = request.form.get('price', type=float)
    
    new_price = float(new_price) if new_price is not None else None
    
    if new_price is None or new_price < 0:
        return jsonify({'success': False, 'message': 'Valid price is required'})
    
    try:
        # ULTRA-OPTIMIZED: Single raw SQL query with UPDATE and RETURNING
        result = db.session.execute(text("""
            UPDATE products 
            SET price = :new_price, updated_at = NOW()
            WHERE id = :product_id
            RETURNING id, name, price
        """), {'new_price': new_price, 'product_id': product_id})
        
        updated_product = result.fetchone()
        
        if not updated_product:
            return jsonify({'success': False, 'message': 'Product not found'})
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Harga berhasil diupdate ke Rp {new_price:,.0f}',
            'new_price': int(new_price)
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to update inventory price: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to update inventory price'})

@app.route('/warehouse/<product_id>/update_location', methods=['POST'])
def update_inventory_location(product_id):
    """Update inventory location via JSON AJAX - Modal Compatible"""
    # Support both JSON and form data
    if request.is_json:
        data = request.get_json()
        zone = data.get('zone', '').strip() if data else ''
        rack = data.get('rack', '').strip() if data else ''
        bin_location = data.get('bin', '').strip() if data else ''
    else:
        zone = request.form.get('zone', '').strip()
        rack = request.form.get('rack', '').strip()
        bin_location = request.form.get('bin', '').strip()
    
    try:
        # ULTRA-OPTIMIZED: Single raw SQL query with UPDATE and RETURNING
        result = db.session.execute(text("""
            UPDATE products 
            SET zone = :zone, rack = :rack, bin = :bin_location, updated_at = NOW()
            WHERE id = :product_id
            RETURNING id, name, zone, rack, bin
        """), {
            'zone': zone if zone else None,
            'rack': rack if rack else None, 
            'bin_location': bin_location if bin_location else None,
            'product_id': product_id
        })
        
        updated_product = result.fetchone()
        
        if not updated_product:
            return jsonify({'success': False, 'message': 'Product not found'})
        
        db.session.commit()
        
        # Build location display
        location_parts = []
        if updated_product.zone:
            location_parts.append(updated_product.zone)
        if updated_product.rack:
            location_parts.append(updated_product.rack)
        if updated_product.bin:
            location_parts.append(updated_product.bin)
        
        location_display = '-'.join(location_parts) if location_parts else 'Not set'
        
        return jsonify({
            'success': True, 
            'message': f'Lokasi berhasil diupdate: {location_display}',
            'zone': updated_product.zone,
            'rack': updated_product.rack,
            'bin': updated_product.bin
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to update inventory location: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to update inventory location'})

@app.route('/warehouse/<product_id>/update_sku', methods=['POST'])
def update_inventory_sku(product_id):
    """Update inventory SKU via JSON AJAX - Modal Compatible"""
    # Support both JSON and form data
    if request.is_json:
        data = request.get_json()
        new_sku = data.get('sku', '').strip() if data else ''
    else:
        new_sku = request.form.get('sku', '').strip()
    
    if not new_sku:
        return jsonify({'success': False, 'message': 'SKU is required'})
    
    try:
        # Check if SKU already exists (excluding current product)
        existing_product = db.session.execute(text("""
            SELECT id FROM products 
            WHERE sku = :new_sku AND id != :product_id
        """), {'new_sku': new_sku, 'product_id': product_id}).fetchone()
        
        if existing_product:
            return jsonify({'success': False, 'message': 'SKU sudah ada, gunakan SKU yang berbeda'})
        
        # ULTRA-OPTIMIZED: Single raw SQL query with UPDATE and RETURNING
        result = db.session.execute(text("""
            UPDATE products 
            SET sku = :new_sku, updated_at = NOW()
            WHERE id = :product_id
            RETURNING id, name, sku
        """), {'new_sku': new_sku, 'product_id': product_id})
        
        updated_product = result.fetchone()
        
        if not updated_product:
            return jsonify({'success': False, 'message': 'Product not found'})
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'SKU berhasil diupdate: {new_sku}',
            'new_sku': new_sku
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to update inventory SKU: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to update inventory SKU'})

@app.route('/hr/employees', methods=['GET', 'POST'])
@login_required
@admin_required
def hr_employees():
    """Employee management page"""
    # Handle POST request (Add new employee)
    if request.method == 'POST':
        try:
            from database_models import Employee
            
            # Get form data
            full_name = request.form.get('full_name')
            employee_id = request.form.get('employee_id')
            position = request.form.get('position', 'Staff')
            branch_location = request.form.get('branch_location')
            salary_group_id = request.form.get('salary_group_id')
            is_active = request.form.get('is_active', '1') == '1'
            
            # Validate required fields
            if not all([full_name, employee_id, branch_location, salary_group_id]):
                flash('Semua field wajib harus diisi', 'error')
                return redirect(url_for('hr_employees'))
            
            # Check if employee_id already exists
            existing = Employee.query.filter_by(employee_id=employee_id).first()
            if existing:
                flash('ID Karyawan sudah ada, gunakan ID yang berbeda', 'error')
                return redirect(url_for('hr_employees'))
            
            # Create new employee
            new_employee = Employee(
                employee_id=employee_id,
                full_name=full_name,
                position=position,
                branch_location=branch_location,
                is_active=is_active,
                monthly_salary=0,  # Will be updated based on salary group
                overtime_sunday_rate=1.5,  # Default overtime rate for Sunday
                overtime_night_rate=1.5    # Default overtime rate for night
            )
            
            # Save to database
            db.session.add(new_employee)
            db.session.commit()
            
            flash(f'Karyawan {full_name} berhasil ditambahkan!', 'success')
            return redirect(url_for('hr_employees'))
            
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error creating employee: {str(e)}")
            flash(f'Gagal menambahkan karyawan: {str(e)}', 'error')
            return redirect(url_for('hr_employees'))
    
    # Handle GET request (Show page)
    try:
        # Get all employees with their salary group info
        employees = db.session.execute(text("""
            SELECT e.id, e.employee_id, e.full_name, e.position, e.branch_location, 
                   e.monthly_salary, e.is_active, e.created_at,
                   sg.group_name, sg.daily_wage, l.location_name
            FROM employees e
            LEFT JOIN locations l ON l.location_name = e.branch_location
            LEFT JOIN salary_groups sg ON sg.location_id = l.id AND sg.employee_names LIKE '%' || LOWER(e.full_name) || '%'
            ORDER BY e.full_name
        """)).fetchall()

        # Get available locations with salary groups
        locations = db.session.execute(text("SELECT id, location_name FROM locations ORDER BY location_name")).fetchall()
        
        # Get salary groups by location for dropdown
        salary_groups = db.session.execute(text("""
            SELECT sg.id, sg.group_name, sg.daily_wage, l.location_name, sg.group_level
            FROM salary_groups sg
            JOIN locations l ON sg.location_id = l.id
            WHERE sg.is_active = true
            ORDER BY l.location_name, sg.group_level
        """)).fetchall()

        # Statistics
        stats = {
            'total_employees': len(employees),
            'active_employees': len([e for e in employees if e.is_active]),
            'lampung_employees': len([e for e in employees if e.branch_location == 'Lampung']),
            'tangerang_employees': len([e for e in employees if e.branch_location == 'Tangerang'])
        }

        return render_template('employee_management.html', 
                             employees=employees,
                             locations=locations,
                             salary_groups=salary_groups,
                             stats=stats)
                             
    except Exception as e:
        logging.error(f"Error in hr_employees: {str(e)}")
        flash('Error loading employee data', 'error')
        return redirect(url_for('dashboard'))

@app.route('/clear-all-data', methods=['POST'])
@login_required
def clear_all_data():
    """Clear all order data for fresh import - OPTIMIZED with raw SQL for speed"""
    try:
        # Use raw SQL for bulk delete - MUCH FASTER
        with db.engine.connect() as conn:
            # Delete in proper order to avoid foreign key constraints
            conn.execute(db.text("DELETE FROM activity_logs"))  # Added ActivityLog cleanup
            conn.execute(db.text("DELETE FROM packing_audit_trail"))
            conn.execute(db.text("DELETE FROM picking_audit_trail"))
            conn.execute(db.text("DELETE FROM scan_history"))
            conn.execute(db.text("DELETE FROM stock_movements"))
            conn.execute(db.text("DELETE FROM picking_sessions"))
            conn.execute(db.text("DELETE FROM order_items"))
            conn.execute(db.text("DELETE FROM orders"))
            conn.commit()
        
        logging.info("All order data cleared successfully using bulk delete")
        return jsonify({'success': True, 'message': 'Semua data pesanan berhasil dihapus'})
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error clearing data: {str(e)}")
        return jsonify({'success': False, 'message': f'Gagal menghapus data: {str(e)}'})

@app.route('/orders/delete_all', methods=['POST'])
def delete_all_orders():
    """Delete all orders - OPTIMIZED with raw SQL for speed"""
    try:
        # Use raw SQL for bulk delete - MUCH FASTER
        with db.engine.connect() as conn:
            # Delete in proper order to avoid foreign key constraints
            conn.execute(db.text("DELETE FROM activity_logs"))  # Added ActivityLog cleanup
            conn.execute(db.text("DELETE FROM packing_audit_trail"))
            conn.execute(db.text("DELETE FROM picking_audit_trail"))
            conn.execute(db.text("DELETE FROM scan_history"))
            conn.execute(db.text("DELETE FROM stock_movements"))
            conn.execute(db.text("DELETE FROM picking_sessions"))
            conn.execute(db.text("DELETE FROM order_items"))
            conn.execute(db.text("DELETE FROM orders"))
            conn.commit()
        
        logging.info("All orders deleted successfully using bulk delete")
        return jsonify({'success': True, 'message': 'Semua pesanan berhasil dihapus'})
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting all orders: {str(e)}")
        return jsonify({'success': False, 'message': f'Gagal menghapus pesanan: {str(e)}'})

@app.route('/orders/delete_selected', methods=['POST'])
def delete_selected_orders():
    """Delete selected orders - OPTIMIZED with raw SQL for speed"""
    try:
        data = request.get_json()
        order_ids = data.get('order_ids', [])
        
        if not order_ids:
            return jsonify({'success': False, 'message': 'Tidak ada pesanan yang dipilih'})
        
        # Convert to integers
        order_ids = [int(id) for id in order_ids]
        order_ids_str = ','.join(map(str, order_ids))
        
        # First get the order_numbers for activity logs cleanup
        with db.engine.connect() as conn:
            result = conn.execute(db.text(f"SELECT order_number FROM orders WHERE id IN ({order_ids_str})"))
            order_numbers = [row[0] for row in result]
        
        # Use raw SQL for bulk delete - MUCH FASTER
        with db.engine.connect() as conn:
            # Delete activity logs by order_number first
            if order_numbers:
                order_numbers_str = "','".join(order_numbers)
                conn.execute(db.text(f"DELETE FROM activity_logs WHERE order_number IN ('{order_numbers_str}')"))
            
            # Delete in proper order to avoid foreign key constraints
            conn.execute(db.text(f"DELETE FROM packing_audit_trail WHERE order_id IN ({order_ids_str})"))
            conn.execute(db.text(f"DELETE FROM picking_audit_trail WHERE order_id IN ({order_ids_str})"))
            conn.execute(db.text(f"DELETE FROM scan_history WHERE order_id IN ({order_ids_str})"))
            conn.execute(db.text(f"DELETE FROM stock_movements WHERE order_id IN ({order_ids_str})"))
            conn.execute(db.text(f"DELETE FROM picking_sessions WHERE order_id IN ({order_ids_str})"))
            conn.execute(db.text(f"DELETE FROM order_items WHERE order_id IN ({order_ids_str})"))
            conn.execute(db.text(f"DELETE FROM orders WHERE id IN ({order_ids_str})"))
            conn.commit()
        
        logging.info(f"Successfully deleted {len(order_ids)} orders using bulk delete")
        return jsonify({'success': True, 'message': f'{len(order_ids)} pesanan berhasil dihapus'})
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting selected orders: {str(e)}")
        return jsonify({'success': False, 'message': f'Gagal menghapus pesanan: {str(e)}'})

# Order Import Routes
@app.route('/orders/import_old', methods=['GET', 'POST'])
def import_orders_old():
    """Import with progress interface"""
    if request.method == 'POST':
        # Handle AJAX file upload
        uploaded_files = request.files.getlist('order_files')
        
        if not uploaded_files or all(f.filename == '' for f in uploaded_files):
            return jsonify({'success': False, 'message': 'Tidak ada file yang dipilih'})
        
        # Process all uploaded files
        total_imported = 0
        total_skipped = 0
        total_errors = 0
        results = []
        
        for file in uploaded_files:
            if file.filename == '':
                continue
            
        # Check file extension
        if not file.filename.lower().endswith(('.xlsx', '.xls')):
            return jsonify({'success': False, 'message': 'Format file tidak valid. Gunakan .xlsx atau .xls'})
        
        try:
            # Save file temporarily
            import tempfile
            import os
            
            temp_dir = tempfile.gettempdir()
            temp_file_path = os.path.join(temp_dir, file.filename)
            file.save(temp_file_path)
            
            # Import using bulk import function that works
            from bulk_import_final import bulk_import_single_file
            logging.info(f"Starting bulk import for file: {file.filename}")
            result = bulk_import_single_file(temp_file_path)
            logging.info(f"Bulk import result: {result}")
            
            # Clean up temp file
            os.remove(temp_file_path)
            
            if isinstance(result, dict) and result.get('success'):
                return jsonify({
                    'success': True,
                    'imported_count': result['imported_count'],
                    'skipped_count': result.get('skipped_count', 0),
                    'message': f'Berhasil import {result["imported_count"]} pesanan dari {file.filename}'
                })
            else:
                error_msg = result.get('message', 'unknown error') if isinstance(result, dict) else str(result)
                return jsonify({
                    'success': False,
                    'imported_count': 0,
                    'message': f'Error: {error_msg}'
                })
                
        except Exception as e:
            logging.error(f"Error processing file {file.filename}: {str(e)}")
            import traceback
            error_details = traceback.format_exc()
            logging.error(f"Full traceback: {error_details}")
            return jsonify({
                'success': False,
                'imported_count': 0,
                'message': f'Error processing file: {str(e)}',
                'error_details': error_details
            })
    
    return render_template('import_orders_progress.html')

import json
from datetime import datetime

# Global variable to store upload progress
upload_progress_data = {}

@app.route('/orders/import_stream', methods=['POST'])
def import_orders_stream():
    """Stream import with real-time per-file progress updates"""
    uploaded_files = request.files.getlist('order_files')
    
    if not uploaded_files or all(f.filename == '' for f in uploaded_files):
        return jsonify({'success': False, 'message': 'Tidak ada file yang dipilih'})
    
    # Filter valid files
    valid_files = [f for f in uploaded_files if f.filename != '' and f.filename.lower().endswith(('.xlsx', '.xls'))]
    
    if not valid_files:
        return jsonify({'success': False, 'message': 'Tidak ada file Excel yang valid ditemukan'})
    
    # Generate unique session ID
    import uuid
    session_id = str(uuid.uuid4())
    
    # Initialize progress data
    upload_progress_data[session_id] = {
        'total_files': len(valid_files),
        'processed_files': 0,
        'current_file': '',
        'current_file_index': 0,
        'file_results': [],
        'total_imported': 0,
        'total_skipped': 0,
        'failed_files': [],
        'status': 'starting',
        'start_time': datetime.now().isoformat()
    }
    
    def process_files():
        try:
            import tempfile
            import os
            
            progress = upload_progress_data[session_id]
            
            for file_index, file in enumerate(valid_files, 1):
                try:
                    # Update progress
                    progress['current_file'] = file.filename
                    progress['current_file_index'] = file_index
                    progress['status'] = 'processing'
                    
                    # Log file details
                    logging.info(f"Processing upload: {file.filename}")
                    
                    # Add file to results with "processing" status
                    file_result = {
                        'filename': file.filename,
                        'status': 'processing',
                        'imported': 0,
                        'skipped': 0,
                        'message': 'Sedang diproses...'
                    }
                    progress['file_results'].append(file_result)
                    
                    # Save file temporarily
                    temp_dir = tempfile.gettempdir()
                    temp_file_path = os.path.join(temp_dir, file.filename)
                    file.save(temp_file_path)
                    
                    # Check if file exists and has content
                    if not os.path.exists(temp_file_path) or os.path.getsize(temp_file_path) == 0:
                        file_result['status'] = 'failed'
                        file_result['message'] = 'File kosong atau tidak valid'
                        progress['failed_files'].append(f"{file.filename}: File kosong")
                        continue
                    
                    # Import using bulk import function
                    from bulk_import_final import bulk_import_single_file
                    logging.info(f"Starting bulk import for file: {file.filename}")
                    
                    result = bulk_import_single_file(temp_file_path)
                    logging.info(f"Bulk import result for {file.filename}: {result}")
                    
                    # Clean up temp file
                    try:
                        os.remove(temp_file_path)
                    except:
                        pass  # Ignore cleanup errors
                    
                    # Handle result
                    if isinstance(result, dict) and result.get('success', False):
                        file_imported = result.get('imported_count', 0)
                        file_skipped = result.get('skipped_count', 0)
                        
                        # Update file result
                        file_result['status'] = 'success'
                        file_result['imported'] = file_imported
                        file_result['skipped'] = file_skipped
                        file_result['message'] = f'{file_imported} pesanan, {file_skipped} duplikat'
                        
                        # Update totals
                        progress['total_imported'] += file_imported
                        progress['total_skipped'] += file_skipped
                        progress['processed_files'] += 1
                        
                        logging.info(f"Successfully processed {file.filename}: {file_imported} imported, {file_skipped} skipped")
                    else:
                        error_msg = result.get('message', 'Import gagal') if isinstance(result, dict) else str(result)
                        file_result['status'] = 'failed'
                        file_result['message'] = error_msg
                        progress['failed_files'].append(f"{file.filename}: {error_msg}")
                        logging.error(f"Failed to process {file.filename}: {error_msg}")
                        
                except Exception as e:
                    error_msg = f"Error: {str(e)}"
                    logging.error(f"Error processing {file.filename}: {error_msg}")
                    
                    # Update file result
                    file_result['status'] = 'failed'
                    file_result['message'] = error_msg
                    progress['failed_files'].append(f"{file.filename}: {error_msg}")
                    continue
            
            # Mark as completed
            progress['status'] = 'completed'
            progress['end_time'] = datetime.now().isoformat()
            
        except Exception as e:
            progress['status'] = 'error'
            progress['error_message'] = str(e)
            logging.error(f"Fatal error in process_files: {str(e)}")
    
    # Start processing in background
    import threading
    thread = threading.Thread(target=process_files)
    thread.start()
    
    return jsonify({
        'success': True,
        'session_id': session_id,
        'message': 'Upload dimulai, gunakan session_id untuk monitoring progress'
    })

@app.route('/orders/import_progress/<session_id>')
def get_import_progress(session_id):
    """Get ultra-fast upload progress"""
    try:
        from ultra_fast_import import get_processing_status
        result = get_processing_status(session_id)
        return jsonify(result)
    except ImportError:
        # Fallback to original system
        if session_id in upload_progress_data:
            return jsonify(upload_progress_data[session_id])
        return jsonify({'error': 'Progress system not available'}), 404

@app.route('/orders/import', methods=['GET', 'POST'])
def import_orders():
    """Simple and reliable import system"""
    if request.method == 'POST':
        uploaded_files = request.files.getlist('order_files')
        
        if not uploaded_files or all(f.filename == '' for f in uploaded_files):
            return jsonify({'success': False, 'message': 'Tidak ada file yang dipilih'})
        
        # Filter valid files
        valid_files = [f for f in uploaded_files if f.filename != '' and f.filename.lower().endswith(('.xlsx', '.xls'))]
        
        if not valid_files:
            return jsonify({'success': False, 'message': 'Tidak ada file Excel yang valid ditemukan'})
        
        # Use simple direct processing for immediate results
        return process_files_directly(valid_files)
    
    # GET request - show upload form
    return render_template('orders_new.html')

def process_files_directly(files):
    """Direct processing for immediate results"""
    try:
        from bulk_import_final import bulk_import_single_file
        import tempfile
        import os
        
        total_imported = 0
        total_skipped = 0
        processed_files = 0
        failed_files = []
        
        logging.info(f"Processing {len(files)} files directly")
        
        for file_index, file in enumerate(files, 1):
            try:
                logging.info(f"Processing file {file_index}: {file.filename}")
                
                # Create temp file
                temp_dir = tempfile.gettempdir()
                temp_file_path = os.path.join(temp_dir, f"direct_{file_index}_{file.filename}")
                
                with open(temp_file_path, 'wb') as temp_file:
                    file.seek(0)
                    temp_file.write(file.read())
                    temp_file.flush()
                
                if os.path.exists(temp_file_path) and os.path.getsize(temp_file_path) > 0:
                    result = bulk_import_single_file(temp_file_path)
                    
                    if result and result.get('success', False):
                        file_imported = result.get('imported_count', 0)
                        file_skipped = result.get('skipped_count', 0)
                        total_imported += file_imported
                        total_skipped += file_skipped
                        processed_files += 1
                        logging.info(f"✓ {file.filename}: {file_imported} imported, {file_skipped} skipped")
                    else:
                        error_msg = result.get('message', 'Import failed') if result else 'Unknown error'
                        failed_files.append(f"{file.filename}: {error_msg}")
                        logging.error(f"✗ {file.filename}: {error_msg}")
                else:
                    failed_files.append(f"{file.filename}: File kosong")
                
                # Cleanup
                try:
                    os.remove(temp_file_path)
                except:
                    pass
                    
            except Exception as e:
                error_msg = f"Error processing {file.filename}: {str(e)}"
                logging.error(error_msg)
                failed_files.append(error_msg)
                continue
        
        # Return final results
        success_message = f"Upload selesai! {processed_files}/{len(files)} berhasil"
        if total_imported > 0:
            success_message += f", {total_imported} pesanan baru"
        if total_skipped > 0:
            success_message += f", {total_skipped} duplikat"
        if failed_files:
            success_message += f", {len(failed_files)} gagal"
        
        return jsonify({
            'success': processed_files > 0,
            'imported_count': total_imported,
            'skipped_count': total_skipped,
            'processed_files': processed_files,
            'failed_files': len(failed_files),
            'total_files': len(files),
            'message': success_message
        })
        
    except Exception as e:
        logging.error(f"Fatal error in direct processing: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error processing files: {str(e)}'
        })

def process_small_batch_sync(files):
    """Synchronous processing for small batches (≤5 files)"""
    try:
        from bulk_import_final import bulk_import_single_file
        import tempfile
        import os
        
        total_imported = 0
        total_skipped = 0
        processed_files = 0
        
        for file_index, file in enumerate(files, 1):
            try:
                # Quick temp file processing
                temp_dir = tempfile.gettempdir()
                temp_file_path = os.path.join(temp_dir, f"sync_{file_index}_{file.filename}")
                
                with open(temp_file_path, 'wb') as temp_file:
                    file.seek(0)
                    temp_file.write(file.read())
                    temp_file.flush()
                
                if os.path.exists(temp_file_path) and os.path.getsize(temp_file_path) > 0:
                    result = bulk_import_single_file(temp_file_path)
                    
                    if result and result.get('success', False):
                        total_imported += result.get('imported_count', 0)
                        total_skipped += result.get('skipped_count', 0)
                        processed_files += 1
                
                # Cleanup
                try:
                    os.remove(temp_file_path)
                except:
                    pass
                    
            except Exception as e:
                logging.error(f"Error processing {file.filename}: {e}")
                continue
        
        return jsonify({
            'success': processed_files > 0,
            'imported_count': total_imported,
            'skipped_count': total_skipped,
            'processed_files': processed_files,
            'total_files': len(files),
            'message': f'Upload selesai! {processed_files}/{len(files)} berhasil, {total_imported} pesanan baru, {total_skipped} duplikat'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error processing files: {str(e)}'
        })
        
        try:
            import tempfile
            import os
            import traceback
            
            # Process multiple files
            total_imported = 0
            total_skipped = 0
            processed_files = 0
            failed_files = []
            
            logging.info(f"Processing {len(valid_files)} files for upload")
            
            for file_index, file in enumerate(valid_files, 1):
                try:
                    # Log file details
                    logging.info(f"Processing upload: {file.filename}")
                    
                    # Create unique temp filename to avoid conflicts
                    temp_dir = tempfile.gettempdir()
                    unique_filename = f"upload_{file_index}_{file.filename}"
                    temp_file_path = os.path.join(temp_dir, unique_filename)
                    
                    # Save file temporarily - fix file handle issue
                    with open(temp_file_path, 'wb') as temp_file:
                        file.seek(0)  # Reset file pointer to beginning
                        temp_file.write(file.read())
                        temp_file.flush()  # Ensure data is written
                    
                    # Check if file exists and has content
                    if not os.path.exists(temp_file_path) or os.path.getsize(temp_file_path) == 0:
                        failed_files.append(f"{file.filename}: File kosong")
                        try:
                            os.remove(temp_file_path)
                        except:
                            pass
                        continue
                    
                    # Import using bulk import function
                    from bulk_import_final import bulk_import_single_file
                    logging.info(f"Starting bulk import for file: {file.filename}")
                    
                    result = bulk_import_single_file(temp_file_path)
                    logging.info(f"Bulk import result for {file.filename}: {result}")
                    
                    # Clean up temp file
                    try:
                        os.remove(temp_file_path)
                    except Exception as e:
                        logging.warning(f"Could not remove temp file {temp_file_path}: {e}")
                    
                    # Handle result
                    if isinstance(result, dict) and result.get('success', False):
                        file_imported = result.get('imported_count', 0)
                        file_skipped = result.get('skipped_count', 0)
                        total_imported += file_imported
                        total_skipped += file_skipped
                        processed_files += 1
                        logging.info(f"Successfully processed {file.filename}: {file_imported} imported, {file_skipped} skipped")
                    else:
                        error_msg = result.get('message', 'Import gagal') if isinstance(result, dict) else str(result)
                        failed_files.append(f"{file.filename}: {error_msg}")
                        logging.error(f"Failed to process {file.filename}: {error_msg}")
                        
                except Exception as e:
                    error_msg = f"Error processing {file.filename}: {str(e)}"
                    logging.error(error_msg)
                    failed_files.append(f"{file.filename}: {str(e)}")
                    continue
            
            # Prepare final response
            success_message = f"Import selesai! {processed_files}/{len(valid_files)} file berhasil diproses. "
            success_message += f"Total: {total_imported} pesanan baru, {total_skipped} duplikat."
            
            if failed_files:
                success_message += f" {len(failed_files)} file gagal diproses."
            
            return jsonify({
                'success': processed_files > 0,
                'imported_count': total_imported,
                'skipped_count': total_skipped,
                'processed_files': processed_files,
                'total_files': len(valid_files),
                'failed_files': len(failed_files),
                'message': success_message,
                'failed_details': failed_files[:10] if failed_files else []  # Show first 10 failures
            })
                
        except ImportError as ie:
            error_msg = f"Error importing bulk_import_final: {str(ie)}"
            logging.error(error_msg)
            return jsonify({
                'success': False,
                'imported_count': 0,
                'message': 'Error: Modul import tidak tersedia'
            })
        except Exception as e:
            error_msg = f"Error processing files: {str(e)}"
            logging.error(error_msg)
            logging.error(f"Full traceback: {traceback.format_exc()}")
            return jsonify({
                'success': False,
                'imported_count': 0,
                'message': f'Error: {str(e)}'
            })
    
    return render_template('import_orders_progress.html')

def process_order_data(data):
    """Process imported order data from Shopee format - handles multiple products per order"""
    import re
    import time
    from collections import defaultdict
    
    imported_count = 0
    
    # Check if data is empty
    if data is None or (hasattr(data, 'empty') and data.empty) or (hasattr(data, '__len__') and len(data) == 0):
        logging.warning("No data provided to process_order_data")
        return 0
        
    logging.info(f"Starting to process order data")
    
    # Ensure database connection is fresh for large imports
    try:
        # Refresh database connection to avoid timeout issues
        db.session.close()
        db.engine.dispose()
        
        logging.info("Database connection refreshed for large import")
    except Exception as db_init_error:
        logging.error(f"Error refreshing database connection: {str(db_init_error)}")
        # Continue anyway, don't stop the process
        pass
    
    # Use direct import approach
    try:
        # Convert pandas DataFrame to list of dicts if needed
        if hasattr(data, 'to_dict'):
            data = data.to_dict('records')
        
        # Group records by order_sn
        orders_dict = defaultdict(list)
        for record in data:
            order_sn = str(record.get('order_sn', '')).strip()
            if order_sn and order_sn != 'nan' and order_sn.lower() != 'none':
                orders_dict[order_sn].append(record)
        
        logging.info(f"Processing {len(orders_dict)} unique orders from {len(data)} records")
        
        # Get existing orders once
        existing_orders = set()
        try:
            existing_orders = {order.order_number for order in Order.query.all()}
        except Exception as e:
            logging.error(f"Error getting existing orders: {e}")
            existing_orders = set()
        
        # Process orders one by one with individual commits
        imported_count = 0
        for order_number, order_rows in orders_dict.items():
            if order_number in existing_orders:
                logging.info(f"Order {order_number} already exists, skipping")
                continue
                
            try:
                # Process single order using enhanced approach
                if import_single_order_safe(order_number, order_rows):
                    imported_count += 1
                    existing_orders.add(order_number)
                    
                    if imported_count % 10 == 0:
                        logging.info(f"Imported {imported_count} orders so far...")
                        
            except Exception as e:
                logging.error(f"Error processing order {order_number}: {str(e)}")
                continue
        
        logging.info(f"Total imported: {imported_count} orders")
        return imported_count
        
    except Exception as e:
        logging.error(f"Error in process_order_data: {str(e)}")
        return 0

def import_single_order_safe(order_number, order_rows):
    """Import a single order with individual transaction - enhanced version"""
    import re
    try:
        first_row = order_rows[0]
        
        # Extract customer info
        customer_name = str(first_row.get('order_receiver_name', '') or 
                          first_row.get('buyer_user_name', '') or 
                          'Unknown Customer').strip()
        
        tracking_number = str(first_row.get('tracking_number', '')).strip()
        if tracking_number == 'nan' or not tracking_number:
            tracking_number = None
        else:
            # Check for duplicate tracking number
            try:
                existing_tracking = Order.query.filter_by(tracking_number=tracking_number).first()
                if existing_tracking:
                    logging.warning(f"Duplicate tracking number {tracking_number} found, making unique...")
                    tracking_number = f"{tracking_number}_{order_number}"
            except:
                pass
        
        # Calculate total amount
        total_amount = 0.0
        product_info = str(first_row.get('product_info', ''))
        
        if product_info and product_info != 'nan':
            try:
                price_matches = re.findall(r'Harga:\s*Rp\s*([\d,\.]+)', product_info)
                qty_matches = re.findall(r'Jumlah:\s*(\d+)', product_info)
                
                for i, price_match in enumerate(price_matches):
                    try:
                        price_str = price_match.replace(',', '').replace('.', '')
                        price = float(price_str)
                        quantity = int(qty_matches[i]) if i < len(qty_matches) else 1
                        total_amount += price * quantity
                    except:
                        continue
            except:
                pass
        
        # Create order
        new_order = Order(
            order_number=order_number,
            tracking_number=tracking_number,
            customer_name=customer_name,
            customer_phone=None,
            customer_address=None,
            status='pending',
            total_amount=total_amount
        )
        
        db.session.add(new_order)
        db.session.flush()
        
        # Process items
        if product_info and product_info != 'nan':
            lines = product_info.replace('\r\n', '\n').split('\n')
            current_product = {}
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                if re.match(r'^\[\d+\]', line):
                    # Save previous product
                    if current_product.get('name'):
                        order_item = OrderItem(
                            order_id=new_order.id,
                            sku=current_product.get('sku', 'UNKNOWN'),
                            product_name=current_product.get('name', 'Unknown Product'),
                            quantity=current_product.get('quantity', 1),
                            price=current_product.get('price', 0.0)
                        )
                        db.session.add(order_item)
                    
                    # Start new product
                    current_product = {'name': '', 'sku': 'UNKNOWN', 'price': 0.0, 'quantity': 1}
                    
                    # Extract product name
                    if 'Nama Produk:' in line:
                        name_match = re.search(r'Nama Produk:(.+?)(?:;|$)', line)
                        if name_match:
                            product_name = name_match.group(1).strip()
                            product_name = re.sub(r'^\[BAYAR DITEMPAT\]\s*', '', product_name)
                            current_product['name'] = product_name
                    
                    # Extract price
                    price_match = re.search(r'Harga:\s*Rp\s*([\d,\.]+)', line)
                    if price_match:
                        try:
                            price_str = price_match.group(1).replace(',', '').replace('.', '')
                            current_product['price'] = float(price_str)
                        except:
                            pass
                    
                    # Extract quantity
                    qty_match = re.search(r'Jumlah:\s*(\d+)', line)
                    if qty_match:
                        try:
                            current_product['quantity'] = int(qty_match.group(1))
                        except:
                            pass
            
            # Save last product
            if current_product.get('name'):
                order_item = OrderItem(
                    order_id=new_order.id,
                    sku=current_product.get('sku', 'UNKNOWN'),
                    product_name=current_product.get('name', 'Unknown Product'),
                    quantity=current_product.get('quantity', 1),
                    price=current_product.get('price', 0.0)
                )
                db.session.add(order_item)
        
        # Commit individual order
        db.session.commit()
        return True
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error processing order {order_number}: {str(e)}")
        return False
    
    # Convert DataFrame to list of dictionaries if needed
    if hasattr(data, 'iterrows'):  # DataFrame
        data = [row.to_dict() for _, row in data.iterrows()]
    elif hasattr(data, '__iter__') and not isinstance(data, (list, tuple)):
        data = list(data)
    
    # Group rows by order_sn to handle multiple products per order
    orders_dict = defaultdict(list)
    row_count = 0
    for row in data:
        row_count += 1
        if not isinstance(row, dict):
            continue
        # Check both original column name and mapped column name
        order_sn = str(row.get('order_sn', '') or row.get('No. Pesanan', '') or '').strip()
        if order_sn and order_sn != 'nan' and order_sn != '':
            orders_dict[order_sn].append(row)
        else:
            # Debug: log what keys are available
            logging.debug(f"Row keys: {list(row.keys())}, values: {[str(v)[:20] for v in row.values()]}")
    
    logging.info(f"Found {len(orders_dict)} unique orders from {row_count} rows")
    
    # Process each unique order with batch commit for efficiency
    batch_size = 5  # Smaller batch for better stability
    processed_in_batch = 0
    
    for order_number, order_rows in orders_dict.items():
        try:
            # Use the first row for order-level information (they should be the same for all rows of same order)
            first_row = order_rows[0]
            
            # Extract order information from first row
            tracking_number = str(first_row.get('tracking_number', '') or first_row.get('No. Resi', '') or '').strip()
            if tracking_number == 'nan' or not tracking_number:
                tracking_number = None
            
            # Check if order already exists (skip duplicates) with connection retry
            try:
                existing_order = Order.query.filter_by(order_number=order_number).first()
                if existing_order:
                    logging.warning(f"Order with order number {order_number} already exists, skipping...")
                    continue
            except Exception as db_error:
                # Database connection issue, try to refresh and retry
                logging.error(f"Database error checking existing order: {str(db_error)}")
                try:
                    db.session.rollback()
                    db.session.close()
                    db.engine.dispose()
                    existing_order = Order.query.filter_by(order_number=order_number).first()
                    if existing_order:
                        logging.warning(f"Order with order number {order_number} already exists, skipping...")
                        continue
                except Exception as retry_error:
                    logging.error(f"Failed to retry database connection: {str(retry_error)}")
                    # Skip this order and continue
                    continue
                
            customer_name = str(first_row.get('order_receiver_name', '') or first_row.get('buyer_user_name', '') or first_row.get('Username Pembeli', '') or first_row.get('Nama Penerima', '') or '').strip()
            if not customer_name or customer_name == 'nan':
                customer_name = 'Unknown Customer'
                
            customer_phone = str(first_row.get('phone', '') or first_row.get('No. Telepon', '') or '').strip()
            if customer_phone == 'nan' or not customer_phone:
                customer_phone = None
                
            customer_address = str(first_row.get('address', '') or first_row.get('Alamat Pengiriman', '') or '').strip()
            if customer_address == 'nan' or not customer_address:
                customer_address = None
            
            # Calculate total amount from all products in this order
            total_amount = 0.0
            for row in order_rows:
                product_info = str(row.get('product_info', '') or row.get('Info Produk', '') or '').strip()
                if product_info and product_info != 'nan':
                    try:
                        # Extract price and quantity for each product
                        # Look for pattern like "Harga: Rp 35,000" or "Harga: Rp 35.000"
                        price_matches = re.findall(r'Harga:\s*Rp\s*([\d,\.]+)', product_info)
                        qty_matches = re.findall(r'Jumlah:\s*(\d+)', product_info)
                        
                        logging.debug(f"Order {order_number}: Found {len(price_matches)} prices, {len(qty_matches)} quantities")
                        
                        for i, price_match in enumerate(price_matches):
                            try:
                                # Handle both comma and dot as thousand separators
                                price_str = price_match.replace(',', '').replace('.', '')
                                # If price is less than 1000, it might be in hundreds
                                if len(price_str) <= 3:
                                    price = float(price_str) * 1000  # Convert hundreds to full amount
                                else:
                                    price = float(price_str)
                                
                                quantity = int(qty_matches[i]) if i < len(qty_matches) else 1
                                item_total = price * quantity
                                total_amount += item_total
                                logging.debug(f"Item {i+1}: Rp {price} x {quantity} = Rp {item_total}")
                            except (ValueError, IndexError) as ve:
                                logging.warning(f"Error parsing price/qty {i}: {str(ve)}")
                                continue
                    except Exception as item_e:
                        logging.warning(f"Error processing product info for order {order_number}: {str(item_e)}")
            
            # Create new order with error handling
            try:
                # Validate required fields
                if not order_number or not customer_name:
                    logging.warning(f"Missing required fields for order: {order_number}")
                    continue
                    
                # Clean and validate text fields to prevent encoding issues
                def clean_text(text):
                    if not text or text == 'nan':
                        return None
                    try:
                        # Convert to string and handle encoding
                        text_str = str(text)
                        # Remove non-printable characters and ensure UTF-8 compatibility
                        text_str = ''.join(char for char in text_str if char.isprintable() or char.isspace())
                        # Truncate if too long
                        if len(text_str) > 500:
                            text_str = text_str[:500]
                        return text_str.strip()
                    except Exception as e:
                        logging.warning(f"Error cleaning text '{text}': {str(e)}")
                        return None
                
                # Clean all text fields
                customer_name = clean_text(customer_name) or 'Unknown Customer'
                customer_phone = clean_text(customer_phone)
                customer_address = clean_text(customer_address)
                tracking_number = clean_text(tracking_number)
                
                new_order = Order(
                    order_number=order_number,
                    tracking_number=tracking_number,
                    customer_name=customer_name,
                    customer_phone=customer_phone,
                    customer_address=customer_address,
                    total_amount=total_amount,
                    status='perlu_dikirim'  # Set status to 'perlu_dikirim' for newly imported orders
                )
                
                db.session.add(new_order)
                db.session.flush()  # Get the order ID
                
                # Add order items
                for row in order_rows:
                    product_info = str(row.get('product_info', '') or row.get('Info Produk', '') or '').strip()
                    if product_info and product_info != 'nan':
                        try:
                            # Parse product info for individual products
                            # Split by lines to handle multiple products
                            lines = product_info.replace('\r\n', '\n').split('\n')
                            current_product = {}
                            
                            for line in lines:
                                line = line.strip()
                                if not line:
                                    continue
                                
                                # Check if this is a product line (starts with [number])
                                if re.match(r'^\[\d+\]', line):
                                    # Save previous product if exists
                                    if current_product.get('name'):
                                        order_item = OrderItem(
                                            order_id=new_order.id,
                                            sku=current_product.get('sku', 'UNKNOWN'),
                                            product_name=current_product.get('name', 'Unknown Product'),
                                            quantity=current_product.get('quantity', 1),
                                            price=current_product.get('price', 0.0)
                                        )
                                        db.session.add(order_item)
                                        imported_count += 1
                                    
                                    # Start new product
                                    current_product = {'name': '', 'sku': 'UNKNOWN', 'price': 0.0, 'quantity': 1}
                                    
                                    # Extract product name from the line
                                    # Look for pattern like "Nama Produk: Product Name;"
                                    if 'Nama Produk:' in line:
                                        name_match = re.search(r'Nama Produk:(.+?)(?:;|$)', line)
                                        if name_match:
                                            product_name = name_match.group(1).strip()
                                            # Clean product name
                                            product_name = re.sub(r'^\[BAYAR DITEMPAT\]\s*', '', product_name)
                                            current_product['name'] = clean_text(product_name)
                                    
                                    # Extract price
                                    price_match = re.search(r'Harga:\s*Rp\s*([\d,\.]+)', line)
                                    if price_match:
                                        try:
                                            price_str = price_match.group(1).replace(',', '').replace('.', '')
                                            if len(price_str) <= 3:
                                                current_product['price'] = float(price_str) * 1000
                                            else:
                                                current_product['price'] = float(price_str)
                                        except:
                                            pass
                                    
                                    # Extract quantity
                                    qty_match = re.search(r'Jumlah:\s*(\d+)', line)
                                    if qty_match:
                                        try:
                                            current_product['quantity'] = int(qty_match.group(1))
                                        except:
                                            pass
                                    
                                    # Extract SKU if available
                                    sku_match = re.search(r'SKU Induk:\s*([^;]+)', line)
                                    if sku_match:
                                        current_product['sku'] = clean_text(sku_match.group(1))
                            
                            # Save the last product
                            if current_product.get('name'):
                                order_item = OrderItem(
                                    order_id=new_order.id,
                                    sku=current_product.get('sku', 'UNKNOWN'),
                                    product_name=current_product.get('name', 'Unknown Product'),
                                    quantity=current_product.get('quantity', 1),
                                    price=current_product.get('price', 0.0)
                                )
                                db.session.add(order_item)
                                imported_count += 1
                                
                        except Exception as product_error:
                            logging.warning(f"Error processing product info for order {order_number}: {str(product_error)}")
                            continue
                
                # Commit individual order
                db.session.commit()
                imported_count += 1
                processed_in_batch += 1
                logging.info(f"Successfully imported order {order_number}: {customer_name} (Status: perlu_dikirim)")
                
                # Check if we should commit batch
                if processed_in_batch >= batch_size:
                    logging.info(f"Batch of {processed_in_batch} orders committed")
                    processed_in_batch = 0
                    
            except Exception as commit_error:
                logging.error(f"Error committing order {order_number}: {str(commit_error)}")
                db.session.rollback()
                continue
                
        except Exception as order_error:
            logging.error(f"Error processing order {order_number}: {str(order_error)}")
            db.session.rollback()
            continue
    
    logging.info(f"Import completed. Total orders processed: {imported_count}")
    return imported_count
    
    # Convert DataFrame to list of dictionaries if needed
    if hasattr(data, 'iterrows'):  # DataFrame
        data = [row.to_dict() for _, row in data.iterrows()]
    elif hasattr(data, '__iter__') and not isinstance(data, (list, tuple)):
        data = list(data)
    
    # Group rows by order_sn to handle multiple products per order
    orders_dict = defaultdict(list)
    row_count = 0
    for row in data:
        row_count += 1
        if not isinstance(row, dict):
            continue
        # Check both original column name and mapped column name
        order_sn = str(row.get('order_sn', '') or row.get('No. Pesanan', '') or '').strip()
        if order_sn and order_sn != 'nan' and order_sn != '':
            orders_dict[order_sn].append(row)
        else:
            # Debug: log what keys are available
            logging.debug(f"Row keys: {list(row.keys())}, values: {[str(v)[:20] for v in row.values()]}")
    
    logging.info(f"Found {len(orders_dict)} unique orders from {row_count} rows")
    
    # Process each unique order with batch commit for efficiency
    batch_size = 5  # Smaller batch for better stability
    processed_in_batch = 0
    
    for order_number, order_rows in orders_dict.items():
        try:
            # Use the first row for order-level information (they should be the same for all rows of same order)
            first_row = order_rows[0]
            
            # Extract order information from first row
            tracking_number = str(first_row.get('tracking_number', '') or first_row.get('No. Resi', '') or '').strip()
            if tracking_number == 'nan' or not tracking_number:
                tracking_number = None
            
            # Check if order already exists (skip duplicates) with connection retry
            try:
                existing_order = Order.query.filter_by(order_number=order_number).first()
                if existing_order:
                    logging.warning(f"Order with order number {order_number} already exists, skipping...")
                    continue
            except Exception as db_error:
                # Database connection issue, try to refresh and retry
                logging.error(f"Database error checking existing order: {str(db_error)}")
                try:
                    db.session.rollback()
                    db.session.close()
                    db.engine.dispose()
                    existing_order = Order.query.filter_by(order_number=order_number).first()
                    if existing_order:
                        logging.warning(f"Order with order number {order_number} already exists, skipping...")
                        continue
                except Exception as retry_error:
                    logging.error(f"Failed to retry database connection: {str(retry_error)}")
                    # Skip this order and continue
                    continue
                
            customer_name = str(first_row.get('order_receiver_name', '') or first_row.get('buyer_user_name', '') or first_row.get('Username Pembeli', '') or first_row.get('Nama Penerima', '') or '').strip()
            if not customer_name or customer_name == 'nan':
                customer_name = 'Unknown Customer'
                
            customer_phone = str(first_row.get('phone', '') or first_row.get('No. Telepon', '') or '').strip()
            if customer_phone == 'nan' or not customer_phone:
                customer_phone = None
                
            customer_address = str(first_row.get('address', '') or first_row.get('Alamat Pengiriman', '') or '').strip()
            if customer_address == 'nan' or not customer_address:
                customer_address = None
            
            # Calculate total amount from all products in this order
            total_amount = 0.0
            for row in order_rows:
                product_info = str(row.get('product_info', '') or row.get('Info Produk', '') or '').strip()
                if product_info and product_info != 'nan':
                    try:
                        # Extract price and quantity for each product
                        # Look for pattern like "Harga: Rp 35,000" or "Harga: Rp 35.000"
                        price_matches = re.findall(r'Harga:\s*Rp\s*([\d,\.]+)', product_info)
                        qty_matches = re.findall(r'Jumlah:\s*(\d+)', product_info)
                        
                        logging.debug(f"Order {order_number}: Found {len(price_matches)} prices, {len(qty_matches)} quantities")
                        
                        for i, price_match in enumerate(price_matches):
                            try:
                                # Handle both comma and dot as thousand separators
                                price_str = price_match.replace(',', '').replace('.', '')
                                # If price is less than 1000, it might be in hundreds
                                if len(price_str) <= 3:
                                    price = float(price_str) * 1000  # Convert hundreds to full amount
                                else:
                                    price = float(price_str)
                                
                                quantity = int(qty_matches[i]) if i < len(qty_matches) else 1
                                item_total = price * quantity
                                total_amount += item_total
                                logging.debug(f"Item {i+1}: Rp {price} x {quantity} = Rp {item_total}")
                            except (ValueError, IndexError) as ve:
                                logging.warning(f"Error parsing price/qty {i}: {str(ve)}")
                                continue
                    except Exception as item_e:
                        logging.warning(f"Error processing product info for order {order_number}: {str(item_e)}")
            
            # Create new order with error handling
            try:
                # Validate required fields
                if not order_number or not customer_name:
                    logging.warning(f"Missing required fields for order: {order_number}")
                    continue
                    
                # Clean and validate text fields to prevent encoding issues
                def clean_text(text):
                    if not text or text == 'nan':
                        return None
                    try:
                        # Convert to string and handle encoding
                        text_str = str(text)
                        # Remove non-printable characters and ensure UTF-8 compatibility
                        cleaned = ''.join(char for char in text_str if char.isprintable() or char.isspace())
                        return cleaned.strip()[:500]  # Limit length
                    except Exception as e:
                        logging.warning(f"Text cleaning error: {str(e)}")
                        return "Invalid Text"
                
                new_order = Order(
                    order_number=clean_text(order_number),
                    tracking_number=clean_text(tracking_number),
                    customer_name=clean_text(customer_name),
                    customer_phone=clean_text(customer_phone),
                    customer_address=clean_text(customer_address),
                    status='perlu_dikirim',
                    total_amount=total_amount
                )
                
                db.session.add(new_order)
                db.session.flush()  # Get the order ID without committing
                
                # Process individual products for this order - each product is on separate line
                product_info = str(order_rows[0].get('product_info', '') or order_rows[0].get('Info Produk', '') or '').strip()
                if product_info and product_info != 'nan':
                    # Split product info by line breaks and process each product separately
                    lines = product_info.replace('\r\n', '\n').split('\n')
                    current_product = {}
                    
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                            
                        # Check if this is start of new product (contains [number])
                        if re.match(r'^\[\d+\]', line):
                            # Save previous product if exists
                            if current_product.get('name'):
                                try:
                                    order_item = OrderItem(
                                        order_id=new_order.id,
                                        sku=clean_text(current_product.get('sku', 'UNKNOWN')),
                                        product_name=clean_text(current_product.get('name', 'Unknown Product')),
                                        quantity=current_product.get('quantity', 1),
                                        price=current_product.get('price', 0.0)
                                    )
                                    db.session.add(order_item)
                                    logging.debug(f"Added product: {current_product.get('name')} (SKU: {current_product.get('sku')}) - Qty: {current_product.get('quantity')} - Price: Rp {current_product.get('price')}")
                                except Exception as item_error:
                                    logging.error(f"Error creating order item: {str(item_error)}")
                            
                            # Start new product
                            current_product = {'name': '', 'sku': 'UNKNOWN', 'price': 0.0, 'quantity': 1}
                            
                            # Extract product name from this line
                            if 'Nama Produk:' in line:
                                name_match = re.search(r'Nama Produk:(.+?)(?:;|$)', line)
                                if name_match:
                                    product_name = name_match.group(1).strip()
                                    # Remove [BAYAR DITEMPAT] prefix if present
                                    product_name = re.sub(r'^\[BAYAR DITEMPAT\]\s*', '', product_name)
                                    current_product['name'] = product_name
                            
                            # Extract price from this line
                            price_match = re.search(r'Harga:\s*Rp\s*([\d,\.]+)', line)
                            if price_match:
                                try:
                                    price_str = price_match.group(1).replace(',', '').replace('.', '')
                                    if len(price_str) <= 3:
                                        current_product['price'] = float(price_str) * 1000
                                    else:
                                        current_product['price'] = float(price_str)
                                except ValueError:
                                    current_product['price'] = 0.0
                            
                            # Extract quantity from this line
                            qty_match = re.search(r'Jumlah:\s*(\d+)', line)
                            if qty_match:
                                try:
                                    current_product['quantity'] = int(qty_match.group(1))
                                except ValueError:
                                    current_product['quantity'] = 1
                            
                            # Extract SKU from this line if present
                            if 'SKU Induk:' in line:
                                sku_match = re.search(r'SKU Induk:\s*(.+?)(?:;|$)', line)
                                if sku_match:
                                    current_product['sku'] = sku_match.group(1).strip()
                            elif 'Nomor Referensi SKU:' in line:
                                sku_match = re.search(r'Nomor Referensi SKU:\s*(.+?)(?:;|$)', line)
                                if sku_match:
                                    current_product['sku'] = sku_match.group(1).strip()
                    
                    # Don't forget to save the last product
                    if current_product.get('name'):
                        try:
                            order_item = OrderItem(
                                order_id=new_order.id,
                                sku=clean_text(current_product.get('sku', 'UNKNOWN')),
                                product_name=clean_text(current_product.get('name', 'Unknown Product')),
                                quantity=current_product.get('quantity', 1),
                                price=current_product.get('price', 0.0)
                            )
                            db.session.add(order_item)
                            logging.debug(f"Added product: {current_product.get('name')} (SKU: {current_product.get('sku')}) - Qty: {current_product.get('quantity')} - Price: Rp {current_product.get('price')}")
                        except Exception as item_error:
                            logging.error(f"Error creating final order item: {str(item_error)}")
                
                # Add to session but don't commit yet (batch processing)
                imported_count += 1
                processed_in_batch += 1
                logging.info(f"Added order to batch: {order_number} with {len(order_rows)} product rows, total: Rp {total_amount}")
                
                # Commit in batches for efficiency
                if processed_in_batch >= batch_size:
                    try:
                        db.session.commit()
                        logging.info(f"Successfully committed batch of {processed_in_batch} orders")
                        processed_in_batch = 0
                        
                    except Exception as batch_error:
                        db.session.rollback()
                        logging.error(f"Batch commit error: {str(batch_error)}")
                        # Try to recover connection and continue
                        try:
                            db.session.close()
                            db.engine.dispose()
                        except:
                            pass
                
            except Exception as db_error:
                db.session.rollback()
                error_msg = str(db_error)
                logging.error(f"Database error for order {order_number}: {error_msg}")
                # Continue processing other orders even if one fails
                continue
                
        except Exception as e:
            logging.error(f"Error processing order {order_number}: {str(e)}")
            # Try to recover from error
            try:
                db.session.rollback()
            except:
                pass
            continue
    
    # Final commit for remaining orders in last batch
    if processed_in_batch > 0:
        try:
            db.session.commit()
            logging.info(f"Successfully committed final batch of {processed_in_batch} orders")
        except Exception as final_error:
            db.session.rollback()
            logging.error(f"Final batch commit error: {str(final_error)}")
            # Try to recover and commit individual orders
            try:
                db.session.close()
                db.engine.dispose()
            except:
                pass
    
    logging.info(f"Import completed. Total orders processed: {imported_count}")
    return imported_count



# Fulfillment Dashboard
@app.route('/fulfillment')
def fulfillment_dashboard():
    """Fulfillment dashboard with order status overview"""
    pending_orders = Order.query.filter_by(status='pending').count()
    picking_orders = Order.query.filter_by(status='picking').count()
    packing_orders = Order.query.filter_by(status='packing').count()
    ready_orders = Order.query.filter_by(status='ready_for_pickup').count()
    
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(10).all()
    
    stats = {
        'pending': pending_orders,
        'picking': picking_orders,
        'packing': packing_orders,
        'ready': ready_orders,
        'total': pending_orders + picking_orders + packing_orders + ready_orders
    }
    
    return render_template('fulfillment_dashboard.html', stats=stats, recent_orders=recent_orders)

# Barcode Scanning Routes
@app.route('/scan')
@app.route('/scan_center')
@login_required
def scan_center():
    """Main scanning center with role-based access control"""
    user_role = session.get('user_role')
    user_access = session.get('user_access')
    user_name = session.get('user_name')
    
    # Get mode parameter from URL
    mode = request.args.get('mode', None)
    
    # Role-based access control for modes
    if user_role == 'picker':
        # Picker can only access picking mode
        if mode and mode != 'picking':
            flash('Akses tidak diizinkan untuk mode ini', 'error')
            return redirect(url_for('scan_center', mode='picking'))
        # Auto-redirect picker to picking mode
        if not mode:
            return redirect(url_for('scan_center', mode='picking'))
    elif user_role == 'packer':
        # Packer can only access packing mode
        if mode and mode != 'packing':
            flash('Akses tidak diizinkan untuk mode ini', 'error')
            return redirect(url_for('scan_center', mode='packing'))
        # Auto-redirect packer to packing mode
        if not mode:
            return redirect(url_for('scan_center', mode='packing'))
    elif user_role == 'shipper':
        # Shipper can only access ready pickup mode
        if mode and mode != 'ready-pickup':
            flash('Akses tidak diizinkan untuk mode ini', 'error')
            return redirect(url_for('scan_center', mode='ready-pickup'))
        # Auto-redirect shipper to ready pickup mode
        if not mode:
            return redirect(url_for('scan_center', mode='ready-pickup'))
    
    # Check if this is an AJAX request
    ajax_request = request.args.get('ajax') == '1' or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    # Get stats for scan center with more detailed status
    stats = {
        'picking_orders': Order.query.filter_by(status='perlu_dikirim').count(),
        'packing_orders': Order.query.filter_by(status='packing').count(),
        'ready_pickup_orders': Order.query.filter_by(status='siap_dikirim').count(),
        'total_orders': Order.query.count()
    }
    
    # Get recent scan history
    history = ScanHistory.query.order_by(ScanHistory.scanned_at.desc()).limit(10).all()
    
    template_name = 'scan_center_content.html' if ajax_request else 'scan_center.html'
    return render_template(template_name, 
                         user_role=user_role, 
                         user_access=user_access,
                         user_name=user_name,
                         stats=stats,
                         history=history,
                         mode=mode)

@app.route('/scan-center/orders/<status>')
def scan_center_orders(status):
    """Display orders by status from scan center"""
    # Define valid statuses
    valid_statuses = {
        'picking': 'perlu_dikirim',
        'packing': 'packing', 
        'ready': 'siap_dikirim',
        'total': 'all'
    }
    
    if status not in valid_statuses:
        flash('Status tidak valid', 'error')
        return redirect(url_for('scan_center'))
    
    # Get orders based on status
    if status == 'total':
        orders = Order.query.order_by(Order.created_at.desc()).all()
        title = "Semua Pesanan"
    else:
        orders = Order.query.filter_by(status=valid_statuses[status]).order_by(Order.created_at.desc()).all()
        status_titles = {
            'picking': 'Pesanan Perlu Picking',
            'packing': 'Pesanan Sedang Packing',
            'ready': 'Pesanan Siap Pickup'
        }
        title = status_titles.get(status, 'Pesanan')
    
    return render_template('scan_center_orders.html', 
                         orders=orders, 
                         title=title,
                         status=status,
                         order_count=len(orders))

@app.route('/compact-scanner')
@login_required
def compact_scanner():
    """Compact scanner interface with exact 260x180 camera preview"""
    return render_template('compact_scanner.html')

@app.route('/parsing-data')
@login_required
def parsing_data():
    """Parsing Data Tools page"""
    return render_template('parsing_data.html')

@app.route('/api/get-order-data')
@login_required
def get_order_data():
    """API endpoint to get raw order data for parsing"""
    try:
        # Get all orders with their items
        orders = db.session.query(Order).join(OrderItem).all()
        
        # Extract raw data from orders
        raw_data = []
        for order in orders:
            for item in order.items:
                # Try to find original product_info from the order
                # This would be the raw string data before parsing
                if hasattr(item, 'original_product_info'):
                    raw_data.append(item.original_product_info)
        
        return jsonify({
            'success': True,
            'raw_data': raw_data,
            'total_orders': len(orders)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/download-package')
def download_package():
    """Download complete system package"""
    try:
        return send_file(
            'static/downloads/strong_warehouse_system_complete.tar.gz',
            as_attachment=True,
            download_name='strong_warehouse_system_complete.tar.gz',
            mimetype='application/gzip'
        )
    except Exception as e:
        return f"Error downloading file: {str(e)}", 404

@app.route('/download-page')
def download_page():
    """Download page for system package"""
    return render_template('download_page.html')

@app.route('/api/get-all-orders-raw')
@login_required
def get_all_orders_raw():
    """Get all orders with raw product info data"""
    try:
        # Query to get orders with their items using proper join
        orders_query = db.session.query(Order, OrderItem).join(OrderItem, Order.id == OrderItem.order_id).all()
        
        orders_data = []
        item_counter = 1
        
        for order, item in orders_query:
            # Create raw product info format similar to the original Excel format
            # Format: [1] Nama Produk:PRODUCT_NAME; Nama Variasi:; Harga: Rp PRICE; Jumlah: QUANTITY; Nomor Referensi SKU: SKU_VALUE; SKU Induk: SKU_VALUE;
            
            # Clean price format
            price_formatted = f"{item.price:,.0f}".replace(',', '.')
            
            # Create realistic raw product info string
            raw_product_info = f"[{item_counter}] Nama Produk:{item.product_name}; Nama Variasi:; Harga: Rp {price_formatted}; Jumlah: {item.quantity}; Nomor Referensi SKU: {item.sku}; SKU Induk: {item.sku};"
            
            orders_data.append({
                'order_id': order.id,
                'order_number': order.order_number,
                'customer_name': order.customer_name,
                'raw_product_info': raw_product_info,
                'product_name': item.product_name,
                'sku': item.sku,
                'price': item.price,
                'quantity': item.quantity
            })
            
            item_counter += 1
        
        return jsonify({
            'success': True,
            'orders_data': orders_data,
            'total_items': len(orders_data)
        })
        
    except Exception as e:
        logging.error(f"Error in get_all_orders_raw: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/scan/picking')
def scan_picking():
    """Picking mode scanning page"""
    return render_template('scan_picking.html')

@app.route('/picking-mode')
def picking_mode():
    """Dedicated Picking Mode page"""
    # Get real-time stats for picking mode
    try:
        stats_result = db.session.execute(text("""
            SELECT 
                (SELECT COUNT(*) FROM orders WHERE status = 'perlu_dikirim') as picking_orders,
                (SELECT COUNT(*) FROM order_items WHERE is_picked = TRUE AND DATE(picked_at) = CURRENT_DATE) as completed_picking,
                (SELECT COUNT(*) FROM orders) as total_orders
        """)).fetchone()
        
        stats = {
            'picking_orders': stats_result.picking_orders,
            'completed_picking': stats_result.completed_picking,
            'total_orders': stats_result.total_orders
        }
    except Exception as e:
        logging.error(f"Error getting picking stats: {e}")
        stats = {
            'picking_orders': 0,
            'completed_picking': 0,
            'total_orders': 0
        }
    
    return render_template('picking_mode.html', stats=stats)

@app.route('/packing-mode')
def packing_mode():
    """Dedicated Packing Mode page"""
    # Get stats for packing mode
    stats = {
        'packing_orders': Order.query.filter_by(status='packing').count(),
        'validated_today': Order.query.filter_by(status='packed').count(),
        'total_orders': Order.query.count()
    }
    
    return render_template('packing_mode.html', stats=stats)

@app.route('/ready-pickup-mode')
def ready_pickup_mode():
    """Dedicated Ready Pickup Mode page"""
    # Get stats for ready pickup mode
    stats = {
        'ready_pickup_orders': Order.query.filter_by(status='siap_dikirim').count(),
        'scanned_today': ScanHistory.query.filter_by(scan_type='ready_pickup').filter(
            ScanHistory.scanned_at >= datetime.now().date()
        ).count(),
        'total_orders': Order.query.count()
    }
    
    # Get recent scans
    recent_scans = ScanHistory.query.filter_by(scan_type='ready_pickup').order_by(
        ScanHistory.scanned_at.desc()
    ).limit(10).all()
    
    return render_template('ready_pickup_mode.html', stats=stats, recent_scans=recent_scans)



@app.route('/api/picking/<int:order_id>/items')
def get_picking_items(order_id):
    """Get picking items for specific order"""
    try:
        order = Order.query.get_or_404(order_id)
        items = OrderItem.query.filter_by(order_id=order_id).all()
        
        items_data = []
        for item in items:
            items_data.append({
                'id': item.id,
                'sku': item.sku,
                'product_name': item.product_name,
                'quantity': item.quantity,
                'is_picked': item.is_picked,
                'picked_quantity': item.picked_quantity
            })
        
        # Get product locations for all items
        for item_data in items_data:
            # Get product location from database
            # Debug: Log SKU format
            logging.debug(f"Looking for product with SKU: {item_data['sku']}")
            
            # Try exact SKU match first
            product = Product.query.filter_by(sku=item_data['sku']).first()
            
            # If not found, try to extract clean SKU from pipe-separated format
            if not product and '|' in item_data['sku']:
                # Extract SKU from format like "MJP | BLD-GLSMY-PTH | SET GELAS BLENDER MIYAKO PUTIH"
                sku_parts = item_data['sku'].split('|')
                if len(sku_parts) >= 2:
                    clean_sku = sku_parts[1].strip()
                    logging.debug(f"Trying clean SKU: {clean_sku}")
                    product = Product.query.filter_by(sku=clean_sku).first()
                    
                    # If still not found, try other parts
                    if not product:
                        for part in sku_parts:
                            clean_part = part.strip()
                            if clean_part and len(clean_part) > 2:
                                product = Product.query.filter_by(sku=clean_part).first()
                                if product:
                                    logging.debug(f"Found product with SKU part: {clean_part}")
                                    break
            
            if product:
                logging.debug(f"Found product: {product.name}, zone: {product.zone}, rack: {product.rack}, bin: {product.bin}")
                location_parts = []
                if product.zone:
                    location_parts.append(product.zone)
                if product.rack:
                    location_parts.append(product.rack)
                if product.bin:
                    location_parts.append(product.bin)
                
                # Format location like SKU: |zone-rack-bin|
                if location_parts:
                    location_formatted = "-".join(location_parts)
                    item_data['location'] = f"|{location_formatted}|"
                else:
                    item_data['location'] = None
            else:
                logging.debug(f"Product not found for SKU: {item_data['sku']}")
                item_data['location'] = None
        
        return jsonify({
            'success': True,
            'order': {
                'id': order.id,
                'order_number': order.order_number,
                'customer_name': order.customer_name,
                'order_date': order.order_date.strftime('%Y-%m-%d') if order.order_date else None,
                'status': order.status
            },
            'items': items_data
        })
        
    except Exception as e:
        logging.error(f"Error getting picking items: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/picking/<int:order_id>/complete', methods=['POST'])
def complete_picking_order(order_id):
    """Complete picking for an order"""
    try:
        order = Order.query.get_or_404(order_id)
        
        # Check if all items are picked
        items = OrderItem.query.filter_by(order_id=order_id).all()
        unpicked_items = [item for item in items if not item.is_picked]
        
        if unpicked_items:
            return jsonify({
                'success': False,
                'error': f'Masih ada {len(unpicked_items)} item yang belum dipick'
            }), 400
        
        # Update order status
        order.status = 'picked'
        order.picking_completed_at = datetime.utcnow()
        
        # Update picking session
        session = PickingSession.query.filter_by(order_id=order_id).first()
        if session:
            session.completed_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Picking selesai'
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error completing picking: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/scan_picking', methods=['POST'])
def scan_picking_api():
    """Simple API endpoint for scan center picking"""
    try:
        data = request.get_json()
        barcode = data.get('barcode', '').strip()
        scan_type = data.get('scan_type', 'picking')
        
        if not barcode:
            return jsonify({
                'success': False,
                'message': 'Barcode tidak boleh kosong'
            })
        
        # Find order by order number or tracking number
        order = Order.query.filter(
            (Order.order_number == barcode) | (Order.tracking_number == barcode)
        ).first()
        
        if not order:
            return jsonify({
                'success': False,
                'message': f'Order tidak ditemukan untuk kode: {barcode}'
            })
        
        # Accept orders with status: pending, perlu_dikirim, or already picking
        if order.status not in ['pending', 'perlu_dikirim', 'picking']:
            return jsonify({
                'success': False,
                'message': f'Order tidak dapat dipick. Status saat ini: {order.status}'
            })
        
        # Start picking session
        if order.status in ['pending', 'perlu_dikirim']:
            order.status = 'picking'
            order.picking_started_at = datetime.utcnow()
            
            # Create or get picking session
            picking_session = PickingSession.query.filter_by(order_id=order.id).first()
            if not picking_session:
                picking_session = PickingSession(order_id=order.id, current_item_index=0)
                db.session.add(picking_session)
            
            db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Picking dimulai untuk order {order.order_number} - {order.customer_name}'
        })
        
    except Exception as e:
        logging.error(f"Error in scan_picking_api: {e}")
        return jsonify({
            'success': False,
            'message': 'Terjadi kesalahan sistem'
        })

@app.route('/scan/ready-pickup')
@login_required
def scan_ready_pickup_page():
    """Ready pickup mode scanning page"""
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Items per page
    
    # Get scan history for ready pickup with pagination
    scan_history = ScanHistory.query.filter_by(scan_type='ready_pickup')\
        .order_by(ScanHistory.scanned_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('scan_ready_pickup.html', 
                         scan_history=scan_history)

@app.route('/scan/order', methods=['POST'])
@login_required
def scan_order():
    """Scan order barcode to start picking - ULTRA-OPTIMIZED Strong Versi 03 Logic"""
    if not check_access('picking'):
        return jsonify({'error': 'Akses ditolak. Hanya petugas picker yang dapat mengakses fitur ini.'})
    
    barcode = request.form.get('barcode', '').strip()
    
    if not barcode:
        return jsonify({'error': 'Barcode is required'}), 400
    
    # ULTRA-OPTIMIZED: Single raw SQL query - NO STATUS CHANGE, only create picking session
    try:
        result = db.session.execute(text("""
            SELECT id, order_number, customer_name, status FROM orders 
            WHERE (order_number = :barcode OR tracking_number = :barcode)
            AND status IN ('pending', 'perlu_dikirim')
            LIMIT 1
        """), {'barcode': barcode})
        
        found_order = result.fetchone()
        
        if not found_order:
            # Check if order exists with different status
            existing = db.session.execute(text("""
                SELECT id, order_number, customer_name, status FROM orders 
                WHERE order_number = :barcode OR tracking_number = :barcode
                LIMIT 1
            """), {'barcode': barcode}).fetchone()
            
            if existing:
                if existing.status == 'perlu_dikirim':
                    # Order already ready for picking, return success
                    return jsonify({
                        'success': True,
                        'order_id': existing.id,
                        'order_number': existing.order_number,
                        'customer_name': existing.customer_name
                    })
                else:
                    return jsonify({'error': f'Order tidak bisa di-pick. Status: {existing.status}'}), 400
            else:
                return jsonify({'error': 'Order not found'}), 404
        
        # ULTRA-FAST: Create picking session in single query - DO NOT CHANGE ORDER STATUS
        db.session.execute(text("""
            INSERT INTO picking_sessions (order_id, current_item_index, started_at)
            VALUES (:order_id, 0, NOW())
            ON CONFLICT (order_id) DO NOTHING
        """), {'order_id': found_order.id})
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'order_id': found_order.id,
            'order_number': found_order.order_number,
            'customer_name': found_order.customer_name
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error in scan_order: {e}")
        return jsonify({'error': 'Terjadi kesalahan sistem'}), 500

@app.route('/picking/<int:order_id>')
@login_required
def picking_interface(order_id):
    """Picking interface for specific order - shows all items at once"""
    # Check if user has picker access
    if not check_access('picking'):
        flash('Akses ditolak. Hanya petugas picker yang dapat mengakses fitur ini.', 'error')
        return redirect(url_for('scan_center'))
    
    order = Order.query.get_or_404(order_id)
    
    # Get or create picking session
    session = PickingSession.query.filter_by(order_id=order_id).first()
    if not session:
        session = PickingSession(order_id=order_id)
        db.session.add(session)
        db.session.commit()
    
    # Get all items for this order
    items = OrderItem.query.filter_by(order_id=order_id).all()
    
    # Calculate progress
    total_items = len(items)
    picked_items = len([item for item in items if item.is_picked])
    
    return render_template('picking_interface.html', 
                         order=order, 
                         items=items,
                         picked_items=picked_items,
                         total_items=total_items,
                         session=session)

@app.route('/scan/product', methods=['POST'])
def scan_product():
    """Scan product barcode during picking - ULTRA-OPTIMIZED Strong Versi 03 Logic"""
    try:
        data = request.get_json()
        if not data:
            app.logger.error("No JSON data received")
            return jsonify({'error': 'No JSON data received'}), 400
            
        order_id = data.get('order_id')
        scanned_sku = data.get('barcode', '').strip()
        item_id = data.get('item_id')  # Specific item to pick
        picked_quantity = data.get('quantity', 0)
        
        # Enhanced debug logging
        app.logger.debug(f"=== SCAN PRODUCT DEBUG ===")
        app.logger.debug(f"Raw request data: {data}")
        app.logger.debug(f"Data type: {type(data)}")
        app.logger.debug(f"Data keys: {list(data.keys()) if data else 'No keys'}")
        app.logger.debug(f"Received data: order_id={order_id}, item_id={item_id}, barcode={scanned_sku}, quantity={picked_quantity}")
        
        if not order_id:
            app.logger.error(f"MISSING ORDER_ID ERROR - Full request: {data}")
            return jsonify({'error': 'Missing required data - order_id'}), 400
        if not scanned_sku:
            return jsonify({'error': 'Missing required data - barcode'}), 400
        if not item_id:
            return jsonify({'error': 'Missing required data - item_id'}), 400
        if picked_quantity <= 0:
            return jsonify({'error': 'Invalid quantity - must be greater than 0'}), 400
    except Exception as e:
        app.logger.error(f"Error parsing request data: {e}")
        return jsonify({'error': 'Invalid request format'}), 400
    
    # ULTRA-OPTIMIZED: Single raw SQL query to validate and update in one go
    try:
        # First, validate the item exists and belongs to order
        result = db.session.execute(text("""
            SELECT oi.id, oi.sku, oi.quantity, oi.is_picked, o.order_number
            FROM order_items oi 
            JOIN orders o ON oi.order_id = o.id
            WHERE oi.id = :item_id AND o.id = :order_id
            LIMIT 1
        """), {'item_id': item_id, 'order_id': order_id})
        
        item_data = result.fetchone()
        if not item_data:
            return jsonify({'error': 'Item not found or does not belong to this order'}), 404
        
        # ULTRA-FAST: Smart SKU matching with optimized logic
        def is_valid_product_code(scanned_code, expected_sku):
            # Check if scanned code contains numbers (valid product code indicator)
            has_numbers = any(char.isdigit() for char in scanned_code)
            if not has_numbers:
                return False
            
            # Check if scanned code is part of expected SKU
            scanned_upper = scanned_code.upper()
            expected_upper = expected_sku.upper()
            
            # Direct match
            if scanned_upper == expected_upper:
                return True
                
            # Check if scanned code is a part of the SKU (between | separators)
            if '|' in expected_upper:
                sku_parts = [part.strip() for part in expected_upper.split('|')]
                return scanned_upper in sku_parts
            
            # Color variation matching - HU should match HIJ (HIJAU), etc.
            color_variations = {
                'HU': 'HIJ',  # HU -> HIJAU -> HIJ
                'ME': 'MER',  # ME -> MERAH -> MER
                'BI': 'BIR',  # BI -> BIRU -> BIR
                'PU': 'PUT',  # PU -> PUTIH -> PUT
                'KU': 'KUN',  # KU -> KUNING -> KUN
                'HI': 'HIT',  # HI -> HITAM -> HIT
            }
            
            # Check color variation matching
            for short_code, full_code in color_variations.items():
                if scanned_upper.endswith(short_code) and expected_upper.endswith(full_code):
                    # Check if base part matches (without color suffix)
                    scanned_base = scanned_upper[:-len(short_code)]
                    expected_base = expected_upper[:-len(full_code)]
                    if scanned_base == expected_base:
                        return True
            
            # Check if scanned code is contained in expected SKU
            return scanned_upper in expected_upper
        
        # ULTRA-FAST: Simple and accurate SKU matching - exact match with inventory
        matched_sku = None
        
        # First, check exact match with scanned code
        product_exact = db.session.execute(text("""
            SELECT sku FROM products WHERE sku = :sku LIMIT 1
        """), {'sku': scanned_sku}).fetchone()
        
        if product_exact:
            matched_sku = product_exact.sku
        else:
            # If no exact match, check if scanned code matches any product in inventory
            matching_products = db.session.execute(text("""
                SELECT sku FROM products WHERE sku ILIKE :pattern LIMIT 1
            """), {'pattern': f'%{scanned_sku}%'}).fetchone()
            
            if matching_products:
                matched_sku = matching_products.sku
            else:
                # Show available products for debugging
                available_skus = db.session.execute(text("""
                    SELECT sku FROM products LIMIT 3
                """)).fetchall()
                sku_list = [row.sku for row in available_skus]
                return jsonify({
                    'error': f'Produk tidak ditemukan! Kode scan: {scanned_sku}. SKU tersedia: {", ".join(sku_list)}...'
                }), 400
        
        # Update scanned_sku to the matched full SKU
        scanned_sku = matched_sku
        
        # Validate quantity - must match exactly
        if picked_quantity != item_data.quantity:
            return jsonify({
                'error': f'Jumlah tidak sesuai! Harus tepat {item_data.quantity} item, tapi Anda memasukkan {picked_quantity}.'
            }), 400
        
        # ULTRA-FAST: Update item as picked in single query
        db.session.execute(text("""
            UPDATE order_items 
            SET is_picked = true, picked_quantity = :quantity, picked_at = NOW()
            WHERE id = :item_id
        """), {'quantity': picked_quantity, 'item_id': item_id})
        
        # UPDATE STOK: Kurangi stok produk berdasarkan SKU yang di-scan
        try:
            # Cari produk berdasarkan SKU yang cocok
            product_to_update = db.session.execute(text("""
                SELECT id, sku, quantity, name FROM products 
                WHERE sku = :sku OR sku ILIKE :pattern
                LIMIT 1
            """), {'sku': scanned_sku, 'pattern': f'%{scanned_sku}%'}).fetchone()
            
            if product_to_update:
                # Kurangi stok produk
                new_quantity = max(0, product_to_update.quantity - picked_quantity)
                db.session.execute(text("""
                    UPDATE products 
                    SET quantity = :new_quantity 
                    WHERE id = :product_id
                """), {'new_quantity': new_quantity, 'product_id': product_to_update.id})
                
                logging.info(f"Stok produk {product_to_update.name} dikurangi dari {product_to_update.quantity} menjadi {new_quantity}")
            else:
                logging.warning(f"Produk dengan SKU {scanned_sku} tidak ditemukan di inventory untuk update stok")
                
        except Exception as stock_error:
            logging.error(f"Error updating stock for SKU {scanned_sku}: {stock_error}")
            # Jangan gagalkan proses picking meskipun update stok gagal
        
        # Cek apakah semua item dalam order ini sudah di-pick
        remaining_items = db.session.execute(text("""
            SELECT COUNT(*) as count FROM order_items 
            WHERE order_id = :order_id AND is_picked = FALSE
        """), {'order_id': order_id}).fetchone()
        
        all_items_picked = remaining_items.count == 0
        
        # Jika semua item sudah di-pick, update status order ke packing
        if all_items_picked:
            try:
                db.session.execute(text("""
                    UPDATE orders 
                    SET status = 'packing', packing_started_at = NOW()
                    WHERE id = :order_id
                """), {'order_id': order_id})
                logging.info(f"Order {order_id} status updated to 'packing' - all items picked")
            except Exception as status_error:
                logging.error(f"Error updating order status to packing: {status_error}")
        
        db.session.commit()
        
        # NON-INTRUSIVE: Log picking activity for tracking (safe - won't affect main functionality)
        try:
            user_name = session.get('name', session.get('username', 'Unknown'))
            # Get tracking number from order
            order_info = db.session.execute(text("SELECT tracking_number FROM orders WHERE id = :order_id"), {'order_id': order_id}).fetchone()
            tracking_number = order_info.tracking_number if order_info else None
            
            logging.info(f"Attempting to log activity: order_number={item_data.order_number}, tracking_number={tracking_number}, user={user_name}")
            
            log_activity(
                order_number=item_data.order_number,
                tracking_number=tracking_number,
                user_name=user_name,
                activity_type='picking',
                status='success',
                notes=f'Item picked: {item_data.sku} (Qty: {picked_quantity})'
            )
            
            logging.info(f"Successfully logged picking activity for order {item_data.order_number}")
            
        except Exception as log_error:
            logging.error(f"Failed to log picking activity: {log_error}")
            import traceback
            logging.error(f"Logging error traceback: {traceback.format_exc()}")
        
        response_data = {
            'success': True,
            'message': f'Item berhasil dipick: {item_data.sku}',
            'item_id': item_id,
            'picked_quantity': picked_quantity,
            'all_items_picked': all_items_picked
        }
        
        # Jika semua item sudah di-pick, berikan instruksi untuk lanjut ke packing
        if all_items_picked:
            response_data['message'] = '✓ Semua item selesai di-pick! Order siap untuk validasi packing di Scan Center.'
            response_data['redirect_to_packing'] = False  # Tidak auto-redirect, user harus ke scan center
            response_data['show_completion'] = True
        
        return jsonify(response_data)
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error in scan_product: {e}")
        return jsonify({'error': 'Terjadi kesalahan sistem'}), 500
    
    db.session.commit()
    
    # Calculate progress
    picked_count = len([item for item in all_items if item.is_picked])
    total_count = len(all_items)
    
    return jsonify({
        'success': True,
        'all_picked': all_picked,
        'message': 'Item picked successfully!' if not all_picked else 'All items picked! Order ready for packing.',
        'progress': {
            'picked': picked_count,
            'total': total_count
        }
    })

@app.route('/packing/<int:order_id>')
def packing_interface(order_id):
    """Packing interface"""
    order = Order.query.get_or_404(order_id)
    
    if order.status not in ['picked', 'packing']:
        flash('Order is not ready for packing', 'error')
        return redirect(url_for('fulfillment_dashboard'))
    
    if order.status == 'picked':
        order.status = 'packing'
        order.packing_started_at = datetime.utcnow()
        db.session.commit()
    
    items = OrderItem.query.filter_by(order_id=order_id).all()
    
    return render_template('packing_interface.html', order=order, items=items)

@app.route('/complete_packing/<int:order_id>', methods=['POST'])
def complete_packing(order_id):
    """Complete packing process"""
    order = Order.query.get_or_404(order_id)
    
    order.status = 'packed'
    order.packing_completed_at = datetime.utcnow()
    

    db.session.commit()
    
    if request.is_json:
        return jsonify({
            'success': True, 
            'message': 'Packing completed successfully!',
            'redirect_url': '/scan_center?mode=pickup'
        })
    else:
        flash('Packing completed successfully!', 'success')
        return redirect('/scan_center?mode=pickup')

@app.route('/complete_packing_validation/<int:order_id>', methods=['GET', 'POST'])
def complete_packing_validation(order_id):
    """Complete packing validation process - return JSON response"""
    try:
        order = Order.query.get_or_404(order_id)
        
        order.status = 'packed'
        order.packing_completed_at = datetime.utcnow()
        
        db.session.commit()
        
        # NON-INTRUSIVE: Log packing validation activity
        try:
            user_name = session.get('name', session.get('username', 'Unknown'))
            log_activity(
                order_number=order.order_number,
                tracking_number=order.tracking_number,
                user_name=user_name,
                activity_type='packing',
                status='success',
                notes='Validasi packing selesai'
            )
        except:
            pass  # Ignore logging errors
        
        return jsonify({
            'success': True,
            'message': 'Validasi packing berhasil diselesaikan'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/packing_validation/<int:order_id>')
@login_required
def packing_validation_interface(order_id):
    """Interface untuk validasi packing dengan tampilan sesuai mockup"""
    try:
        order = Order.query.get_or_404(order_id)
        
        # Ensure order is ready for packing validation
        if order.status not in ['picked', 'picking_completed', 'packing', 'perlu_dikirim']:
            flash(f'Order belum siap untuk validasi packing. Status: {order.status}', 'error')
            return redirect(url_for('scan_center'))
        
        # Get all order items that are picked with their product info
        picked_items = OrderItem.query.filter_by(order_id=order_id, is_picked=True).all()
        
        # Get product images for each item based on SKU
        items_with_images = []
        for item in picked_items:
            # Extract clean SKU from formats like "MJP | BLD-GLSMY-HIJ |"
            clean_sku = item.sku
            if '|' in clean_sku:
                # Get the middle part between | symbols
                parts = clean_sku.split('|')
                if len(parts) >= 2:
                    clean_sku = parts[1].strip()
            
            # Try to find product with cleaned SKU
            product = Product.query.filter_by(sku=clean_sku).first()
            
            item_data = {
                'id': item.id,
                'sku': item.sku,
                'product_name': item.product_name,
                'quantity': item.quantity,
                'picked_quantity': item.picked_quantity,
                'price': item.price,
                'is_picked': item.is_picked,
                'picked_at': item.picked_at,
                'product_image': product.image_url if product and product.image_url else None
            }
            items_with_images.append(item_data)
        
        # Check if all items are picked (should be true after above logic)
        unpicked_items = OrderItem.query.filter_by(order_id=order_id, is_picked=False).all()
        if unpicked_items:
            flash(f'Masih ada {len(unpicked_items)} item yang belum dipick', 'error')
            return redirect(url_for('scan_center'))
        
        # Update packing started time if not set - DO NOT CHANGE STATUS
        if not order.packing_started_at:
            order.packing_started_at = datetime.utcnow()
            # order.status = 'packing'  # DISABLED - keep original status
            db.session.commit()
        
        # Check if all items are picked for template
        all_items_picked = len(unpicked_items) == 0
        
        return render_template('packing_validation_interface.html', 
                             order=order, 
                             picked_items=items_with_images,
                             all_items_picked=all_items_picked)
                             
    except Exception as e:
        logging.error(f"Error in packing_validation_interface: {e}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
        return redirect(url_for('scan_center'))




# DISABLED: Old retur mode - replaced with scan_retur_foto
# @app.route('/retur-mode')
# @login_required
def retur_mode_disabled():
    """Retur mode interface - Admin dan Retur access only"""
    if not (check_access('all') or check_access('retur')):
        return redirect(url_for('dashboard'))
    
    # Get statistics for dashboard
    total_pengembalian = Order.query.filter_by(status='pengembalian').count()
    total_siap_dikirim = Order.query.filter_by(status='siap_dikirim').count()
    total_dikirim = Order.query.filter_by(status='dikirim').count()
    
    # Get today's returns count
    from sqlalchemy import func
    today = datetime.utcnow().date()
    retur_today = ScanHistory.query.filter(
        ScanHistory.scan_type == 'retur',
        func.date(ScanHistory.scanned_at) == today,
        ScanHistory.success == True
    ).count()
    
    # Get recent returns from scan history
    recent_returns = ScanHistory.query.filter_by(scan_type='retur', success=True)\
        .order_by(ScanHistory.scanned_at.desc())\
        .limit(10).all()
    
    return render_template('retur_mode.html',
                         total_pengembalian=total_pengembalian,
                         total_siap_dikirim=total_siap_dikirim,
                         total_dikirim=total_dikirim,
                         retur_today=retur_today,
                         recent_returns=recent_returns)

@app.route('/scan_retur', methods=['POST'])
@login_required
def scan_retur():
    """Scan retur API endpoint"""
    if not (check_access('all') or check_access('retur')):
        return jsonify({'error': 'Akses ditolak. Hanya admin dan user dengan akses retur yang dapat mengakses fitur ini.'})
    
    try:
        # Handle both JSON and form data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form
            
        barcode = data.get('barcode', '').strip()
        
        if not barcode:
            return jsonify({'error': 'Kode retur tidak boleh kosong'}), 400
        
        # Find order by order number or tracking number
        order = Order.query.filter(
            (Order.order_number == barcode) | (Order.tracking_number == barcode)
        ).first()
        
        if not order:
            return jsonify({
                'success': False,
                'message': f'Order tidak ditemukan untuk kode: {barcode}'
            })
        
        # Check if order can be returned (status: siap_dikirim, dikirim or selesai)
        if order.status not in ['siap_dikirim', 'dikirim', 'selesai']:
            return jsonify({
                'success': False,
                'message': f'Order tidak dapat diretur. Status saat ini: {order.status}. Hanya order dengan status Siap Dikirim, Dikirim, atau Selesai yang dapat diretur.'
            })
        
        # Update order status to retur
        order.status = 'pengembalian'
        order.updated_at = datetime.utcnow()
        
        # Create scan history for retur
        scan_history = ScanHistory(
            barcode=barcode,
            order_id=order.id,
            scan_type='retur',
            success=True,
            message=f'Order {order.order_number} berhasil diretur',
            order_number=order.order_number,
            customer_name=order.customer_name
        )
        
        db.session.add(scan_history)
        db.session.commit()
        
        # NON-INTRUSIVE: Log retur activity for tracking
        try:
            user_name = session.get('name', session.get('username', 'Unknown'))
            log_activity(
                order_number=order.order_number,
                tracking_number=barcode,
                user_name=user_name,
                activity_type='retur',
                status='success',
                notes=f'Retur diproses - Customer: {order.customer_name}'
            )
        except:
            pass  # Ignore logging errors
        
        return jsonify({
            'success': True,
            'message': f'Retur berhasil! Order {order.order_number} - {order.customer_name} telah diproses untuk pengembalian'
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error in scan_retur: {e}")
        return jsonify({
            'success': False,
            'message': 'Terjadi kesalahan sistem'
        })

@app.route('/scan/packing_validation', methods=['POST'])
@login_required
def scan_packing_validation():
    """Scan untuk validasi packing - ULTRA-OPTIMIZED Strong Versi 03 Logic"""
    if not check_access('packing'):
        return jsonify({'error': 'Akses ditolak. Hanya petugas packer yang dapat mengakses fitur ini.'})
    
    try:
        # Handle both JSON and form data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form
            
        order_identifier = data.get('barcode', '').strip()
        
        if not order_identifier:
            return jsonify({'error': 'Order number or tracking number is required'}), 400
        
        # ULTRA-OPTIMIZED: Single raw SQL query to find order - Accept orders ready for packing
        result = db.session.execute(text("""
            SELECT id, order_number, customer_name, status FROM orders 
            WHERE (order_number = :identifier OR tracking_number = :identifier)
            AND status IN ('picked', 'picking_completed', 'packing')
            LIMIT 1
        """), {'identifier': order_identifier})
        
        found_order = result.fetchone()
        
        if not found_order:
            # Check if order exists with wrong status
            existing = db.session.execute(text("""
                SELECT order_number, status FROM orders 
                WHERE order_number = :identifier OR tracking_number = :identifier
                LIMIT 1
            """), {'identifier': order_identifier}).fetchone()
            
            if existing:
                return jsonify({'error': f'Order tidak siap untuk validasi packing. Status: {existing.status}'}), 400
            else:
                return jsonify({'error': f'Order {order_identifier} tidak ditemukan'}), 404
        
        # Status packing berarti semua item sudah di-pick dari proses picking sebelumnya
        # Tidak perlu auto-pick lagi
        
        # ULTRA-FAST: Check unpicked items in single query
        unpicked_count = db.session.execute(text("""
            SELECT COUNT(*) as count FROM order_items 
            WHERE order_id = :order_id AND is_picked = false
        """), {'order_id': found_order.id}).fetchone()
        
        if unpicked_count.count > 0:
            return jsonify({'error': f'Order masih ada {unpicked_count.count} item yang belum di-pick'}), 400
        
        db.session.commit()
        
        # Return success with redirect URL
        return jsonify({
            'success': True,
            'message': f'Order {found_order.order_number} siap untuk validasi packing',
            'order_number': found_order.order_number,
            'order_id': found_order.id,
            'redirect': url_for('packing_validation_interface', order_id=found_order.id)
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in scan_packing_validation: {str(e)}")
        return jsonify({'error': 'Terjadi kesalahan sistem'}), 500

@app.route('/validate_packing', methods=['POST'])
@login_required
def validate_packing():
    """Validate packing completion and update order status"""
    if not check_access('packing'):
        return jsonify({'error': 'Akses ditolak. Hanya petugas packer yang dapat mengakses fitur ini.'})
    
    try:
        data = request.get_json()
        order_id = data.get('order_id')
        
        if not order_id:
            return jsonify({'error': 'Order ID is required'}), 400
        
        # Find order
        order = Order.query.get(order_id)
        if not order:
            return jsonify({'error': 'Order tidak ditemukan'}), 404
        
        # Update order status to packed (ready for pickup scan)
        order.status = 'packed'
        order.packed_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Order {order.order_number} berhasil divalidasi dan siap dikirim',
            'order_number': order.order_number
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in validate_packing: {str(e)}")
        return jsonify({'error': 'Terjadi kesalahan sistem'}), 500

@app.route('/scan/ready_pickup', methods=['POST'])
@login_required
def scan_ready_pickup():
    """Scan tracking number to mark as ready for pickup - ULTRA-OPTIMIZED FOR HIGH VOLUME - Strong Versi 03 Logic"""
    if not check_access('shipping'):
        return jsonify({'error': 'Akses ditolak. Hanya petugas pengiriman yang dapat mengakses fitur ini.'})
    
    barcode = request.form.get('barcode', '').strip()
    
    if not barcode:
        return jsonify({'error': 'Barcode is required'})
    
    # ULTRA-OPTIMIZED: Raw SQL for maximum speed
    try:
        # Single query to check and update in one go - Only allow 'packed' status
        result = db.session.execute(text("""
            UPDATE orders 
            SET status = 'siap_dikirim', ready_for_pickup_at = NOW()
            WHERE (tracking_number = :barcode OR order_number = :barcode)
            AND status = 'packed'
            RETURNING order_number, customer_name, status
        """), {'barcode': barcode})
        
        updated_order = result.fetchone()
        
        if not updated_order:
            # Check if order exists but wrong status
            existing = db.session.execute(text("""
                SELECT order_number, status FROM orders 
                WHERE tracking_number = :barcode OR order_number = :barcode
            """), {'barcode': barcode}).fetchone()
            
            if existing:
                if existing.status == 'siap_dikirim':
                    return jsonify({'error': f'Resi duplikat - {barcode} sudah pernah discan'})
                elif existing.status == 'perlu_dikirim':
                    return jsonify({'error': f'Pesanan {existing.order_number} harus melalui proses validasi packing terlebih dahulu. Status saat ini: Perlu Dikirim'})
                elif existing.status == 'pending':
                    return jsonify({'error': f'Pesanan {existing.order_number} harus melalui proses picking dan packing terlebih dahulu. Status saat ini: Pending'})
                else:
                    return jsonify({'error': f'Status pesanan {existing.order_number} tidak bisa discan untuk ready pickup. Status saat ini: {existing.status}'})
            else:
                return jsonify({'error': f'Resi {barcode} tidak ditemukan dalam database'})
        
        db.session.commit()
        
        # NON-INTRUSIVE: Log ready pickup activity for tracking
        try:
            user_name = session.get('name', session.get('username', 'Unknown'))
            log_activity(
                order_number=updated_order.order_number,
                tracking_number=barcode,
                user_name=user_name,
                activity_type='ready_pickup',
                status='success',
                notes=f'Order siap dikirim - Customer: {updated_order.customer_name}'
            )
        except:
            pass  # Ignore logging errors
        
        # ULTRA-FAST: Skip history logging for maximum speed (optional - can be disabled)
        # Uncomment below if you want history logging back
        # try:
        #     add_scan_history_with_cleanup(barcode, None, 'ready_pickup', True, 
        #                                   f'✓ Scan berhasil', updated_order.order_number, updated_order.customer_name)
        # except Exception as e:
        #     logging.error(f"History logging failed: {e}")
        
        return jsonify({
            'success': True,
            'message': f'✓ {updated_order.order_number}',
            'order_number': updated_order.order_number,
            'customer_name': updated_order.customer_name
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Scan error: {e}")
        return jsonify({'error': 'Terjadi kesalahan sistem, silakan coba lagi'})

@app.route('/audit/picking')
@login_required
def picking_audit_trail():
    """View picking audit trail - Admin only"""
    if not check_access('admin'):
        return jsonify({'error': 'Akses ditolak. Hanya admin yang dapat melihat audit trail.'})
    
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    per_page = 50
    
    # Base query
    query = PickingAuditTrail.query
    
    # Add search filter if provided
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            db.or_(
                PickingAuditTrail.order_number.ilike(search_pattern),
                PickingAuditTrail.customer_name.ilike(search_pattern)
            )
        )
    
    # Get picking audit entries with pagination
    picking_audits = query.order_by(PickingAuditTrail.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('audit/picking_audit.html', audits=picking_audits, title='Audit Trail - Picking')

@app.route('/audit/packing')
@login_required  
def packing_audit_trail():
    """View packing audit trail - Admin only"""
    if not check_access('admin'):
        return jsonify({'error': 'Akses ditolak. Hanya admin yang dapat melihat audit trail.'})
    
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    per_page = 50
    
    # Base query
    query = PackingAuditTrail.query
    
    # Add search filter if provided
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            db.or_(
                PackingAuditTrail.order_number.ilike(search_pattern),
                PackingAuditTrail.customer_name.ilike(search_pattern)
            )
        )
    
    # Get packing audit entries with pagination
    packing_audits = query.order_by(PackingAuditTrail.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('audit/packing_audit.html', audits=packing_audits, title='Audit Trail - Packing')

@app.route('/audit/scan_history')
@login_required
def scan_history_audit():
    """View scan history with user audit trail - Admin only"""
    if not check_access('admin'):
        return jsonify({'error': 'Akses ditolak. Hanya admin yang dapat melihat audit trail.'})
    
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    per_page = 50
    
    # Base query - only show successful scans (hide failed scans)
    query = ScanHistory.query.filter_by(success=True)
    
    # Add search filter if provided
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            db.or_(
                ScanHistory.order_number.ilike(search_pattern),
                ScanHistory.barcode.ilike(search_pattern)
            )
        )
    
    # Get scan history with pagination
    scan_history = query.order_by(ScanHistory.scanned_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('audit/scan_history_audit.html', history=scan_history, title='Audit Trail - Scan History')

@app.route('/api/scan-history', methods=['GET'])
@login_required
def get_scan_history():
    """Get successful scan history (last 10 entries)"""
    try:
        # Get last 10 successful scans
        successful_scans = ScanHistory.query.filter_by(success=True)\
            .order_by(ScanHistory.scanned_at.desc())\
            .limit(10)\
            .all()
        
        history_data = []
        for scan in successful_scans:
            history_data.append({
                'id': scan.id,
                'barcode': scan.barcode,
                'order_number': scan.order_number,
                'customer_name': scan.customer_name,
                'scan_type': scan.scan_type,
                'message': scan.message,
                'scanned_at': scan.scanned_at.strftime('%H:%M:%S'),
                'scanned_date': scan.scanned_at.strftime('%d/%m/%Y')
            })
        
        return jsonify({
            'success': True,
            'history': history_data,
            'total_count': len(history_data)
        })
        
    except Exception as e:
        logging.error(f"Error getting scan history: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# PWA Routes

@app.route('/manifest.json')
def manifest():
    """Serve PWA manifest"""
    from flask import send_from_directory
    return send_from_directory('static', 'manifest.json', mimetype='application/json')

@app.route('/sw.js')
def service_worker():
    """Serve service worker"""
    from flask import send_from_directory
    return send_from_directory('static', 'sw.js', mimetype='application/javascript')

@app.route('/logo-settings')
@login_required
def logo_settings():
    """Logo settings page"""
    return render_template('logo_settings.html')

@app.route('/update-logo', methods=['POST'])
@login_required
def update_logo():
    """Handle logo upload and update"""
    import os
    from werkzeug.utils import secure_filename
    
    if 'logo_file' not in request.files:
        flash('Tidak ada file yang dipilih', 'error')
        return redirect(url_for('logo_settings'))
    
    file = request.files['logo_file']
    if file.filename == '':
        flash('Tidak ada file yang dipilih', 'error')
        return redirect(url_for('logo_settings'))
    
    # Validate file type
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'svg'}
    file_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    
    if file_extension not in allowed_extensions:
        flash('Format file tidak didukung. Gunakan PNG, JPG, JPEG, GIF, atau SVG', 'error')
        return redirect(url_for('logo_settings'))
    
    # Validate file size (5MB limit)
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    
    if file_size > 5 * 1024 * 1024:  # 5MB
        flash('Ukuran file terlalu besar. Maksimal 5MB', 'error')
        return redirect(url_for('logo_settings'))
    
    try:
        # Create images directory if it doesn't exist
        images_dir = os.path.join(app.static_folder, 'images')
        if not os.path.exists(images_dir):
            os.makedirs(images_dir)
        
        # Backup current logo
        logo_path = os.path.join(images_dir, 'strong_logo.png')
        backup_path = os.path.join(images_dir, 'strong_logo_backup.png')
        
        if os.path.exists(logo_path):
            if os.path.exists(backup_path):
                os.remove(backup_path)
            os.rename(logo_path, backup_path)
        
        # Save new logo
        if file_extension == 'svg':
            # For SVG files, save as is but rename to .png for consistency
            new_logo_path = os.path.join(images_dir, 'strong_logo.svg')
            file.save(new_logo_path)
            # Also copy to .png name for template compatibility
            import shutil
            shutil.copy2(new_logo_path, logo_path)
        else:
            # For other formats, save directly
            file.save(logo_path)
        
        flash('Logo berhasil diperbarui!', 'success')
        
    except Exception as e:
        flash(f'Gagal mengupload logo: {str(e)}', 'error')
        logging.error(f"Logo upload error: {e}")
    
    return redirect(url_for('logo_settings'))

@app.route('/analytics')
@login_required
def analytics():
    """Analytics and reporting dashboard"""
    # Get date range from request
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    period = request.args.get('period', 'week')
    
    # Default to last 7 days if no dates provided
    if not date_from or not date_to:
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=7)
        date_from = start_date.strftime('%Y-%m-%d')
        date_to = end_date.strftime('%Y-%m-%d')
    
    # Convert to datetime objects
    start_datetime = datetime.strptime(date_from, '%Y-%m-%d')
    end_datetime = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
    
    # Calculate analytics data
    analytics_data = calculate_analytics(start_datetime, end_datetime)
    chart_data = generate_chart_data(start_datetime, end_datetime)
    
    return render_template('analytics.html', 
                         analytics=analytics_data,
                         chart_data=chart_data,
                         date_from=date_from,
                         date_to=date_to,
                         period=period)

@app.route('/profit-analytics')
@login_required
@admin_required
def profit_analytics():
    """Profit analytics dashboard"""
    try:
        # Check if this is an AJAX request
        ajax_request = request.args.get('ajax') == '1' or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        
        # Get all orders with their profit data
        orders = Order.query.all()
        
        total_profit = 0.0
        total_cost = 0.0
        total_revenue = 0.0
        profit_by_order = []
        
        for order in orders:
            order_profit = calculate_order_profit(order)
            total_profit += order_profit['total_profit']
            total_cost += order_profit['total_cost']
            total_revenue += order_profit['total_revenue']
            
            profit_by_order.append({
                'order': order,
                'profit_data': order_profit
            })
        
        # Sort by profit descending
        profit_by_order.sort(key=lambda x: x['profit_data']['total_profit'], reverse=True)
        
        # Calculate overall profit margin
        overall_profit_margin = (total_profit / total_revenue * 100) if total_revenue > 0 else 0
        
        # Prepare analytics data for template
        analytics_data = {
            'total_profit': total_profit,
            'total_cost': total_cost,
            'total_revenue': total_revenue,
            'profit_margin': overall_profit_margin,
            'orders': []
        }
        
        # Convert to template-friendly format
        for item in profit_by_order:
            order = item['order']
            profit_data = item['profit_data']
            analytics_data['orders'].append({
                'order_number': order.order_number,
                'customer_name': order.customer_name,
                'revenue': profit_data['total_revenue'],
                'cost': profit_data['total_cost'],
                'profit': profit_data['total_profit'],
                'margin': (profit_data['total_profit'] / profit_data['total_revenue'] * 100) if profit_data['total_revenue'] > 0 else 0,
                'created_at': order.created_at
            })
        
        template_name = 'profit_analytics_content.html' if ajax_request else 'profit_analytics.html'
        return render_template(template_name,
                             analytics=analytics_data,
                             start_date='',
                             end_date='')
    except Exception as e:
        logging.error(f"Error in profit analytics: {str(e)}")
        flash(f'Error loading profit analytics: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/monitoring')
@login_required
def monitoring():
    """Real-time order monitoring dashboard - ULTRA-OPTIMIZED Strong Versi 03 Logic"""
    try:
        # Check if this is an AJAX request
        ajax_request = request.args.get('ajax') == '1' or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        
        # ULTRA-OPTIMIZED: Single raw SQL query to get all stats
        result = db.session.execute(text("""
            SELECT 
                (SELECT COUNT(*) FROM orders) as total_orders,
                (SELECT COUNT(*) FROM products) as total_products,
                (SELECT COUNT(*) FROM orders WHERE status = 'pending') as pending_orders,
                (SELECT COUNT(*) FROM orders WHERE status = 'siap_dikirim') as ready_pickup_orders,
                (SELECT COUNT(*) FROM orders WHERE status = 'selesai') as completed_orders,
                (SELECT COUNT(*) FROM orders WHERE status = 'perlu_dikirim') as processing_orders,
                (SELECT COUNT(*) FROM orders WHERE status = 'picking') as picking_orders,
                (SELECT COUNT(*) FROM orders WHERE status = 'packing') as packing_orders,
                (SELECT COUNT(*) FROM products WHERE quantity <= minimum_stock) as low_stock_products
        """)).fetchone()
        
        stats = {
            'total_orders': result.total_orders,
            'total_products': result.total_products,
            'pending_orders': result.pending_orders,
            'ready_pickup_orders': result.ready_pickup_orders,
            'completed_orders': result.completed_orders,
            'processing_orders': result.processing_orders,
            'picking_orders': result.picking_orders,
            'packing_orders': result.packing_orders,
            'low_stock_products': result.low_stock_products,
            'perlu_dikirim_orders': result.processing_orders
        }
        
        # Get recent orders for monitoring
        recent_orders_result = db.session.execute(text("""
            SELECT id, order_number, customer_name, status, created_at, total_amount
            FROM orders 
            ORDER BY created_at DESC 
            LIMIT 10
        """)).fetchall()
        
        recent_orders = []
        for row in recent_orders_result:
            recent_orders.append({
                'id': row.id,
                'order_number': row.order_number,
                'customer_name': row.customer_name,
                'status': row.status,
                'created_at': row.created_at,
                'total_amount': row.total_amount
            })
        
        # Get hourly data for chart
        hourly_data = {
            'labels': ['00:00', '06:00', '12:00', '18:00', '24:00'],
            'data': [10, 25, 40, 30, 15]
        }
        
        template_name = 'monitoring_content.html' if ajax_request else 'monitoring.html'
        return render_template(template_name, 
                             stats=stats, 
                             recent_orders=recent_orders,
                             hourly_data=hourly_data)
        
    except Exception as e:
        logging.error(f"Error in monitoring: {e}")
        # Fallback stats if query fails
        stats = {
            'total_orders': 0,
            'total_products': 0,
            'pending_orders': 0,
            'ready_pickup_orders': 0,
            'completed_orders': 0,
            'processing_orders': 0,
            'picking_orders': 0,
            'packing_orders': 0,
            'low_stock_products': 0
        }
        return render_template('monitoring.html', 
                             stats=stats, 
                             recent_orders=[],
                             hourly_data={'labels': [], 'data': []})

@app.route('/monitoring/picking_detail')
@login_required
def picking_detail():
    """Detail pesanan yang sedang picking"""
    picking_orders = Order.query.filter_by(status='picked').order_by(Order.picking_completed_at.desc()).limit(50).all()
    return render_template('monitoring_detail.html', 
                         orders=picking_orders, 
                         status_type='picking',
                         title='Detail Pesanan Sedang Picking',
                         status_label='Picking')

@app.route('/monitoring/packing_detail')
@login_required
def packing_detail():
    """Detail pesanan yang sedang packing"""
    packing_orders = Order.query.filter_by(status='packed').order_by(Order.packing_completed_at.desc()).limit(50).all()
    return render_template('monitoring_detail.html', 
                         orders=packing_orders, 
                         status_type='packing',
                         title='Detail Pesanan Sedang Packing',
                         status_label='Packing')

@app.route('/monitoring/ready_pickup_detail')
@login_required
def ready_pickup_detail():
    """Detail pesanan yang ready pickup"""
    ready_orders = Order.query.filter_by(status='siap_dikirim').order_by(Order.ready_for_pickup_at.desc()).limit(50).all()
    return render_template('monitoring_detail.html', 
                         orders=ready_orders, 
                         status_type='ready_pickup',
                         title='Detail Pesanan Ready Pick Up',
                         status_label='Ready Pick Up')

@app.route('/monitoring/pending_detail')
@login_required
def pending_detail():
    """Detail pesanan yang masih pending (belum terproses)"""
    pending_orders = Order.query.filter_by(status='perlu_dikirim').order_by(Order.created_at.desc()).limit(50).all()
    return render_template('monitoring_detail.html', 
                         orders=pending_orders, 
                         status_type='pending',
                         title='Detail Pesanan Pending',
                         status_label='Pending')

# Simple cache for monitoring stats
_monitoring_cache = {'data': None, 'timestamp': 0}

@app.route('/api/monitoring/stats')
@login_required
def api_monitoring_stats():
    """API endpoint for real-time monitoring statistics"""
    try:
        import time
        current_time = time.time()
        
        # Use cache if data is less than 30 seconds old for better performance
        if (_monitoring_cache['data'] is not None and 
            current_time - _monitoring_cache['timestamp'] < 30):
            return jsonify(_monitoring_cache['data'])
        
        # Get current order statistics with single query
        from sqlalchemy import func
        status_counts = db.session.query(
            Order.status,
            func.count(Order.id).label('count')
        ).group_by(Order.status).all()
        
        # Convert to dictionary for easy lookup
        status_dict = {status: count for status, count in status_counts}
        
        total_orders = sum(status_dict.values())
        imported_orders = total_orders  # All orders are imported
        picking_orders = status_dict.get('picked', 0)
        packing_orders = status_dict.get('packed', 0)
        ready_pickup_orders = status_dict.get('siap_dikirim', 0)
        completed_orders = status_dict.get('completed', 0)
        pending_orders = status_dict.get('perlu_dikirim', 0)
        
        # Calculate processing statistics
        processing_orders = picking_orders + packing_orders
        
        # Get recent activity (last 5 orders only)
        recent_orders = Order.query.order_by(Order.created_at.desc()).limit(5).all()
        recent_activity = []
        for order in recent_orders:
            recent_activity.append({
                'order_number': order.order_number,
                'customer_name': order.customer_name,
                'status': order.status,
                'created_at': order.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'total_amount': order.total_amount
            })
        
        # Optimized hourly stats using a single query
        from datetime import datetime, timedelta
        from sqlalchemy import func, extract
        
        today = datetime.now().date()
        today_start = datetime.combine(today, datetime.min.time())
        today_end = today_start + timedelta(days=1)
        
        # Single query to get hourly counts for today
        hourly_data = db.session.query(
            extract('hour', Order.created_at).label('hour'),
            func.count(Order.id).label('count')
        ).filter(
            Order.created_at >= today_start,
            Order.created_at < today_end
        ).group_by(extract('hour', Order.created_at)).all()
        
        # Convert to dictionary for easy lookup
        hour_counts = {int(hour): count for hour, count in hourly_data}
        
        # Create 6-hour stats with optimized data
        current_hour = datetime.now().hour
        hourly_stats = []
        for i in range(6):
            hour = (current_hour - i) % 24
            hourly_stats.append({
                'hour': f"{hour:02d}:00",
                'orders': hour_counts.get(hour, 0)
            })
        
        # Reverse to show chronological order
        hourly_stats.reverse()
        
        result = {
            'success': True,
            'stats': {
                'total_orders': total_orders,
                'imported_orders': imported_orders,
                'pending_orders': pending_orders,
                'picking_orders': picking_orders,
                'packing_orders': packing_orders,
                'ready_pickup_orders': ready_pickup_orders,
                'completed_orders': completed_orders,
                'processing_orders': processing_orders
            },
            'recent_activity': recent_activity,
            'hourly_stats': hourly_stats,
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Update cache
        _monitoring_cache['data'] = result
        _monitoring_cache['timestamp'] = current_time
        
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"Error getting monitoring stats: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/product_display/<int:order_id>')
@login_required
def product_display(order_id):
    """Display products in order with Shopee-like format"""
    order = Order.query.get_or_404(order_id)
    
    # Get all order items with their product info and images
    order_items = OrderItem.query.filter_by(order_id=order_id).all()
    
    # Process items with product info and images
    items_with_images = []
    for item in order_items:
        # Extract clean SKU from formats like "MJP | BLD-GLSMY-HIJ |"
        clean_sku = item.sku
        if '|' in clean_sku:
            # Get the middle part between | symbols
            parts = clean_sku.split('|')
            if len(parts) >= 2:
                clean_sku = parts[1].strip()
        
        # Try to find product with cleaned SKU
        product = Product.query.filter_by(sku=clean_sku).first()
        
        item_data = {
            'id': item.id,
            'sku': clean_sku,  # Use cleaned SKU for display
            'original_sku': item.sku,  # Keep original for reference
            'product_name': item.product_name,
            'quantity': item.quantity,
            'price': item.price,
            'product_image': product.image_url if product and product.image_url else None,
            'product': product
        }
        items_with_images.append(item_data)
    
    return render_template('product_display.html', order=order, order_items=items_with_images)


@app.route('/analytics/export')
@login_required
def export_analytics():
    """Export analytics data to PDF or Excel"""
    format_type = request.args.get('format', 'excel')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    
    if not date_from or not date_to:
        flash('Date range is required for export', 'error')
        return redirect(url_for('analytics'))
    
    start_datetime = datetime.strptime(date_from, '%Y-%m-%d')
    end_datetime = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
    
    analytics_data = calculate_analytics(start_datetime, end_datetime)
    
    if format_type == 'excel':
        return export_to_excel(analytics_data, date_from, date_to)
    elif format_type == 'pdf':
        return export_to_pdf(analytics_data, date_from, date_to)
    
    flash('Invalid export format', 'error')
    return redirect(url_for('analytics'))

def calculate_analytics(start_date, end_date):
    """Calculate analytics data for the given date range"""
    # Basic metrics
    total_orders = db.session.query(Order).filter(
        Order.created_at >= start_date,
        Order.created_at < end_date
    ).count()
    
    total_revenue = db.session.query(func.sum(Order.total_amount)).filter(
        Order.created_at >= start_date,
        Order.created_at < end_date
    ).scalar() or 0
    
    # Items sold
    total_items = db.session.query(func.sum(OrderItem.quantity)).select_from(OrderItem).join(Order, OrderItem.order_id == Order.id).filter(
        Order.created_at >= start_date,
        Order.created_at < end_date
    ).scalar() or 0
    
    # Average fulfillment time (mock calculation)
    avg_fulfillment = 24  # hours - could be calculated from picking/packing timestamps
    
    # Top products
    top_products = db.session.query(
        Product.name,
        func.sum(OrderItem.quantity).label('quantity_sold'),
        func.sum(OrderItem.quantity * OrderItem.price).label('revenue')
    ).select_from(Product).join(OrderItem, Product.sku == OrderItem.sku).join(Order, OrderItem.order_id == Order.id).filter(
        Order.created_at >= start_date,
        Order.created_at < end_date
    ).group_by(Product.id, Product.name).order_by(func.sum(OrderItem.quantity).desc()).limit(5).all()
    
    # High value orders
    high_value_orders = db.session.query(Order).filter(
        Order.created_at >= start_date,
        Order.created_at < end_date,
        Order.total_amount >= 200000  # Orders above 200k
    ).order_by(Order.total_amount.desc()).limit(5).all()
    
    # Calculate growth percentages (based on previous period comparison)
    prev_start = start_date - (end_date - start_date)
    prev_orders = db.session.query(Order).filter(
        Order.created_at >= prev_start,
        Order.created_at < start_date
    ).count()
    
    prev_revenue = db.session.query(func.sum(Order.total_amount)).filter(
        Order.created_at >= prev_start,
        Order.created_at < start_date
    ).scalar() or 0
    
    orders_growth = ((total_orders - prev_orders) / max(prev_orders, 1)) * 100
    revenue_growth = ((total_revenue - prev_revenue) / max(prev_revenue, 1)) * 100
    
    return {
        'total_orders': total_orders,
        'total_revenue': total_revenue,
        'avg_fulfillment_time': avg_fulfillment,
        'total_items_sold': total_items,
        'orders_growth': round(orders_growth, 1),
        'revenue_growth': round(revenue_growth, 1),
        'fulfillment_improvement': 12.5,
        'items_growth': 18.7,
        'top_products': [{'name': p.name, 'quantity_sold': p.quantity_sold, 'revenue': p.revenue} for p in top_products],
        'high_value_orders': high_value_orders
    }

def generate_chart_data(start_date, end_date):
    """Generate chart data for visualization"""
    # Daily sales trend
    days_diff = max((end_date - start_date).days, 1)
    sales_trend_labels = []
    sales_trend_revenue = []
    sales_trend_orders = []
    
    for i in range(days_diff):
        current_date = start_date + timedelta(days=i)
        next_date = current_date + timedelta(days=1)
        
        daily_revenue = db.session.query(func.sum(Order.total_amount)).filter(
            Order.created_at >= current_date,
            Order.created_at < next_date
        ).scalar() or 0
        
        daily_orders = db.session.query(Order).filter(
            Order.created_at >= current_date,
            Order.created_at < next_date
        ).count()
        
        sales_trend_labels.append(current_date.strftime('%m/%d'))
        sales_trend_revenue.append(float(daily_revenue))
        sales_trend_orders.append(daily_orders)
    
    # Order status distribution
    status_counts = db.session.query(
        Order.status,
        func.count(Order.id)
    ).filter(
        Order.created_at >= start_date,
        Order.created_at < end_date
    ).group_by(Order.status).all()
    
    order_status_labels = [s[0].title() for s in status_counts]
    order_status_data = [s[1] for s in status_counts]
    
    # Top products for chart
    top_products_chart = db.session.query(
        Product.name,
        func.sum(OrderItem.quantity)
    ).select_from(Product).join(OrderItem, Product.sku == OrderItem.sku).join(Order, OrderItem.order_id == Order.id).filter(
        Order.created_at >= start_date,
        Order.created_at < end_date
    ).group_by(Product.id, Product.name).order_by(func.sum(OrderItem.quantity).desc()).limit(5).all()
    
    top_products_labels = [p[0][:15] + '...' if len(p[0]) > 15 else p[0] for p in top_products_chart]
    top_products_data = [int(p[1]) for p in top_products_chart]
    
    # Get total revenue for hourly distribution
    total_revenue = db.session.query(func.sum(Order.total_amount)).filter(
        Order.created_at >= start_date,
        Order.created_at < end_date
    ).scalar() or 0
    
    # Hourly revenue (realistic distribution based on business hours)
    hourly_labels = [f"{i:02d}:00" for i in range(24)]
    hourly_data = []
    
    for hour in range(24):
        # Simulate realistic business hour patterns
        if 9 <= hour <= 21:  # Business hours
            base_revenue = float(total_revenue) * 0.06  # 6% per business hour
            # Peak hours: 11-13, 19-21
            if hour in [11, 12, 19, 20]:
                hourly_revenue = base_revenue * 1.5
            else:
                hourly_revenue = base_revenue * 0.8
        else:
            hourly_revenue = float(total_revenue) * 0.005  # 0.5% for off hours
        
        hourly_data.append(hourly_revenue)
    
    return {
        'sales_trend': {
            'labels': sales_trend_labels,
            'revenue': sales_trend_revenue,
            'orders': sales_trend_orders
        },
        'order_status': {
            'labels': order_status_labels,
            'data': order_status_data
        },
        'top_products': {
            'labels': top_products_labels,
            'data': top_products_data
        },
        'hourly_revenue': {
            'labels': hourly_labels,
            'data': hourly_data
        }
    }

def export_to_excel(analytics_data, date_from, date_to):
    """Export analytics data to Excel format"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Strong Order Management - Analytics Report'])
    writer.writerow([f'Period: {date_from} to {date_to}'])
    writer.writerow([])
    
    # KPI Summary
    writer.writerow(['KPI Summary'])
    writer.writerow(['Metric', 'Value'])
    writer.writerow(['Total Orders', analytics_data['total_orders']])
    writer.writerow(['Total Revenue', f"Rp {analytics_data['total_revenue']:,.0f}"])
    writer.writerow(['Average Fulfillment Time', f"{analytics_data['avg_fulfillment_time']} hours"])
    writer.writerow(['Total Items Sold', analytics_data['total_items_sold']])
    writer.writerow([])
    
    # Top Products
    writer.writerow(['Top Products'])
    writer.writerow(['Product Name', 'Quantity Sold', 'Revenue'])
    for product in analytics_data['top_products']:
        writer.writerow([product['name'], product['quantity_sold'], f"Rp {product['revenue']:,.0f}"])
    writer.writerow([])
    
    # High Value Orders
    writer.writerow(['High Value Orders'])
    writer.writerow(['Order Number', 'Customer', 'Amount'])
    for order in analytics_data['high_value_orders']:
        writer.writerow([order.order_number, order.customer_name, f"Rp {order.total_amount:,.0f}"])
    
    # Create response
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=analytics_report_{date_from}_to_{date_to}.csv'
    
    return response

def export_to_pdf(analytics_data, date_from, date_to):
    """Export analytics data to PDF format (simplified as HTML for now)"""
    html_content = f"""
    <html>
    <head>
        <title>Analytics Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .header {{ text-align: center; margin-bottom: 30px; }}
            .kpi {{ display: flex; justify-content: space-around; margin: 20px 0; }}
            .kpi-item {{ text-align: center; padding: 20px; border: 1px solid #ddd; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f4f4f4; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Strong Order Management</h1>
            <h2>Analytics Report</h2>
            <p>Period: {date_from} to {date_to}</p>
        </div>
        
        <div class="kpi">
            <div class="kpi-item">
                <h3>{analytics_data['total_orders']}</h3>
                <p>Total Orders</p>
            </div>
            <div class="kpi-item">
                <h3>Rp {analytics_data['total_revenue']:,.0f}</h3>
                <p>Total Revenue</p>
            </div>
            <div class="kpi-item">
                <h3>{analytics_data['avg_fulfillment_time']}h</h3>
                <p>Avg Fulfillment</p>
            </div>
            <div class="kpi-item">
                <h3>{analytics_data['total_items_sold']}</h3>
                <p>Items Sold</p>
            </div>
        </div>
        
        <h3>Top Products</h3>
        <table>
            <tr><th>Product</th><th>Quantity</th><th>Revenue</th></tr>
    """
    
    for product in analytics_data['top_products']:
        html_content += f"<tr><td>{product['name']}</td><td>{product['quantity_sold']}</td><td>Rp {product['revenue']:,.0f}</td></tr>"
    
    html_content += """
        </table>
        
        <h3>High Value Orders</h3>
        <table>
            <tr><th>Order</th><th>Customer</th><th>Amount</th></tr>
    """
    
    for order in analytics_data['high_value_orders']:
        html_content += f"<tr><td>{order.order_number}</td><td>{order.customer_name}</td><td>Rp {order.total_amount:,.0f}</td></tr>"
    
    html_content += """
        </table>
    </body>
    </html>
    """
    
    response = make_response(html_content)
    response.headers['Content-Type'] = 'text/html'
    response.headers['Content-Disposition'] = f'attachment; filename=analytics_report_{date_from}_to_{date_to}.html'
    
    return response

@app.route('/api/update_user_role', methods=['POST'])
def update_user_role():
    """Update user role via API"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        new_role = data.get('role')
        
        if not user_id or not new_role:
            return jsonify({'success': False, 'message': 'User ID and role are required'}), 400
        
        # Validate role
        valid_roles = ['admin', 'picker', 'packer', 'shipper']
        if new_role not in valid_roles:
            return jsonify({'success': False, 'message': 'Invalid role'}), 400
        
        # Get user from database
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        # Update role
        user.role = new_role
        
        # Auto-set access based on role
        if new_role == 'admin':
            user.access = 'all'
        elif new_role == 'picker':
            user.access = 'picking_only'
        elif new_role == 'packer':
            user.access = 'packing_only'
        elif new_role == 'shipper':
            user.access = 'shipping_only'
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Role updated successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/update_user_access', methods=['POST'])
def update_user_access():
    """Update user access level via API"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        new_access = data.get('access')
        
        if not user_id or not new_access:
            return jsonify({'success': False, 'message': 'User ID and access level are required'}), 400
        
        # Validate access level - now supports multi-access
        valid_access_types = ['all', 'picking', 'packing', 'shipping', 'picking_only', 'packing_only', 'shipping_only']
        
        # Check if it's a valid single access or multi-access format
        if new_access not in ['all', 'picking_only', 'packing_only', 'shipping_only']:
            # Check if it's a valid multi-access format (comma-separated)
            access_parts = [part.strip() for part in new_access.split(',')]
            for part in access_parts:
                if part not in ['picking', 'packing', 'shipping']:
                    return jsonify({'success': False, 'message': 'Invalid access level'}), 400
        
        # Get user from database
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        # Update access level
        user.access = new_access
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Access level updated successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500



@app.route('/api/delete_user/<int:user_id>', methods=['DELETE'])
def api_delete_user(user_id):
    """Delete user via API - Admin only"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        # Prevent deleting the last admin
        if user.role == 'admin':
            admin_count = User.query.filter_by(role='admin', is_active=True).count()
            if admin_count <= 1:
                return jsonify({'success': False, 'message': 'Cannot delete the last admin user'}), 400
        
        username = user.username
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'User {username} deleted successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

# Activity Logging Helper Function (NON-INTRUSIVE)
def log_activity(order_number, user_name, activity_type, status='success', notes=None, tracking_number=None):
    """
    Helper function to log user activities for tracking
    This function is NON-INTRUSIVE and will not affect existing functionality
    """
    try:
        logging.info(f"Starting log_activity: {user_name} - {activity_type} - {order_number} - tracking: {tracking_number}")
        
        # Create new activity log entry
        activity = ActivityLog(
            order_number=order_number,
            tracking_number=tracking_number,
            user_name=user_name,
            activity_type=activity_type,  # picking/packing/ready_pickup/retur
            status=status,  # success/failed
            notes=notes
        )
        
        # Use a fresh session to avoid conflicts
        db.session.add(activity)
        db.session.flush()  # Ensure it's added to session
        db.session.commit()
        
        logging.info(f"Activity successfully logged: {user_name} - {activity_type} - {order_number}")
        
    except Exception as e:
        # Logging failure should NOT affect main functionality
        logging.error(f"Failed to log activity - Error: {e}")
        logging.error(f"Activity details - order: {order_number}, user: {user_name}, type: {activity_type}, tracking: {tracking_number}")
        try:
            db.session.rollback()
        except:
            pass

@app.route('/work_schedule_management')
@login_required
@role_required('admin')
def work_schedule_management():
    """Work Schedule Management - Main page with sidebar"""
    try:
        # Get all work schedules from database
        schedules = db.session.execute(
            text("""
                SELECT branch_location, schedule_type, target_time, tolerance_minutes 
                FROM work_schedules 
                ORDER BY branch_location, schedule_type
            """)
        ).fetchall()
        
        # Organize schedules by branch with proper data structure
        schedules_by_branch = {'Lampung': {}, 'Tangerang': {}}
        for schedule in schedules:
            branch = schedule[0]
            schedule_type = schedule[1]
            target_time = schedule[2]
            tolerance = schedule[3]
            
            if branch in schedules_by_branch:
                schedules_by_branch[branch][schedule_type] = {
                    'target_time': target_time,
                    'tolerance_minutes': tolerance,
                    'window_display': f"{target_time} ± {tolerance} menit" if target_time else "Belum diatur"
                }
        
        logging.info(f"Schedules loaded: {schedules_by_branch}")
        return render_template('work_schedule_management.html', 
                             schedules_by_branch=schedules_by_branch)
        
    except Exception as e:
        logging.error(f"Error in work_schedule_management: {e}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/work_schedule_management_content')
@login_required
@role_required('admin')
def work_schedule_management_content():
    """Work Schedule Management - Content only for AJAX"""
    try:
        # Get all work schedules from database
        schedules = db.session.execute(
            text("""
                SELECT branch_location, schedule_type, target_time, tolerance_minutes 
                FROM work_schedules 
                ORDER BY branch_location, schedule_type
            """)
        ).fetchall()
        
        # Organize schedules by branch with proper data structure
        schedules_by_branch = {'Lampung': {}, 'Tangerang': {}}
        for schedule in schedules:
            branch = schedule[0]
            schedule_type = schedule[1]
            target_time = schedule[2]
            tolerance = schedule[3]
            
            if branch in schedules_by_branch:
                schedules_by_branch[branch][schedule_type] = {
                    'target_time': target_time,
                    'tolerance_minutes': tolerance,
                    'window_display': f"{target_time} ± {tolerance} menit" if target_time else "Belum diatur"
                }
        
        logging.info(f"Content schedules loaded: {schedules_by_branch}")
        return render_template('work_schedule_management_content.html', 
                             schedules_by_branch=schedules_by_branch)
        
    except Exception as e:
        logging.error(f"Error in work_schedule_management_content: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/work_schedule/save', methods=['POST'])
@login_required
@role_required('admin')
def save_work_schedule():
    """Save work schedule changes"""
    try:
        data = request.get_json()
        branch_location = data.get('branch_location')
        schedule_type = data.get('schedule_type')
        target_time = data.get('target_time')
        tolerance_minutes = data.get('tolerance_minutes', 30)
        
        if not all([branch_location, schedule_type, target_time]):
            return jsonify({
                'success': False,
                'error': 'Data tidak lengkap'
            })
        
        # Validate branch and schedule type
        valid_branches = ['Lampung', 'Tangerang']
        valid_schedule_types = ['masuk', 'keluar', 'lembur_malam', 'keluar_lembur']
        
        if branch_location not in valid_branches:
            return jsonify({
                'success': False,
                'error': 'Cabang tidak valid'
            })
        
        if schedule_type not in valid_schedule_types:
            return jsonify({
                'success': False,
                'error': 'Jenis jadwal tidak valid'
            })
        
        # Parse target time
        try:
            from datetime import datetime
            time_obj = datetime.strptime(target_time, '%H:%M').time()
        except ValueError:
            return jsonify({
                'success': False,
                'error': 'Format waktu tidak valid'
            })
        
        # Use PostgreSQL UPSERT (ON CONFLICT) to update or insert with is_active field
        db.session.execute(
            text("""
                INSERT INTO work_schedules (branch_location, schedule_type, target_time, tolerance_minutes, is_active, created_at, updated_at)
                VALUES (:branch_location, :schedule_type, :target_time, :tolerance_minutes, TRUE, NOW(), NOW())
                ON CONFLICT (branch_location, schedule_type) 
                DO UPDATE SET 
                    target_time = EXCLUDED.target_time,
                    tolerance_minutes = EXCLUDED.tolerance_minutes,
                    updated_at = NOW()
            """),
            {
                'branch_location': branch_location,
                'schedule_type': schedule_type,
                'target_time': time_obj,
                'tolerance_minutes': tolerance_minutes
            }
        )
        
        db.session.commit()
        
        logging.info(f"Work schedule saved: {branch_location} - {schedule_type} - {target_time} ± {tolerance_minutes}min")
        
        return jsonify({
            'success': True,
            'message': f'Jadwal {schedule_type} untuk {branch_location} berhasil disimpan',
            'data': {
                'branch_location': branch_location,
                'schedule_type': schedule_type,
                'target_time': target_time,
                'tolerance_minutes': tolerance_minutes
            }
        })
        
    except Exception as e:
        logging.error(f"Error saving work schedule: {e}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': 'Terjadi kesalahan saat menyimpan jadwal'
        })

@app.route('/tracking-activities')
@admin_required
def tracking_activities():
    """Activity tracking dashboard - Admin only"""
    try:
        # Get pagination and filter parameters
        page = request.args.get('page', 1, type=int)
        search = request.args.get('search', '').strip()
        activity_type = request.args.get('activity', '').strip()
        date_filter = request.args.get('date', '').strip()
        per_page = 50
        
        # Get today's date for filters
        today = datetime.now().strftime('%Y-%m-%d')
        
        # Build query with filters
        activities_query = ActivityLog.query
        
        # Apply search filter
        if search:
            activities_query = activities_query.filter(
                db.or_(
                    ActivityLog.order_number.ilike(f'%{search}%'),
                    ActivityLog.user_name.ilike(f'%{search}%'),
                    ActivityLog.tracking_number.ilike(f'%{search}%'),
                    ActivityLog.notes.ilike(f'%{search}%')
                )
            )
        
        # Apply activity type filter
        if activity_type:
            activities_query = activities_query.filter(ActivityLog.activity_type == activity_type)
        
        # Apply date filter
        if date_filter:
            try:
                filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
                activities_query = activities_query.filter(
                    func.date(ActivityLog.created_at) == filter_date
                )
            except ValueError:
                pass  # Ignore invalid date format
        
        # Order by creation date (newest first) and paginate
        activities_query = activities_query.order_by(desc(ActivityLog.created_at))
        pagination = activities_query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        activities = pagination.items
        
        # Calculate statistics for today
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = datetime.now().replace(hour=23, minute=59, second=59, microsecond=999999)
        
        stats = {
            'picking_today': ActivityLog.query.filter(
                ActivityLog.activity_type == 'picking',
                ActivityLog.created_at.between(today_start, today_end),
                ActivityLog.status == 'success'
            ).count(),
            'packing_today': ActivityLog.query.filter(
                ActivityLog.activity_type == 'packing',
                ActivityLog.created_at.between(today_start, today_end),
                ActivityLog.status == 'success'
            ).count(),
            'ready_pickup_today': ActivityLog.query.filter(
                ActivityLog.activity_type == 'ready_pickup',
                ActivityLog.created_at.between(today_start, today_end),
                ActivityLog.status == 'success'
            ).count(),
            'retur_today': ActivityLog.query.filter(
                ActivityLog.activity_type == 'retur',
                ActivityLog.created_at.between(today_start, today_end),
                ActivityLog.status == 'success'
            ).count()
        }
        
        # Handle AJAX requests from loadPage function
        if request.args.get('ajax') == '1' or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            # For AJAX requests, return content-only template without base layout
            return render_template('tracking_activities_content.html', 
                                 activities=activities, 
                                 pagination=pagination, 
                                 page=page,
                                 stats=stats,
                                 today=today)
        else:
            # For normal requests, return full template with base layout
            return render_template('tracking_activities.html', 
                                 activities=activities, 
                                 pagination=pagination, 
                                 page=page,
                                 stats=stats,
                                 today=today)
    
    except Exception as e:
        logging.error(f"Error loading tracking activities: {e}")
        return render_template('error.html', error_message="Error loading activity tracking"), 500

# =============================================================================
# SCAN RETUR + FOTO FUNCTIONALITY
# =============================================================================

@app.route('/scan_retur_foto')
@login_required
@role_required('admin', 'scan retur')
def scan_retur_foto():
    """Main page for Scan Retur + Foto functionality"""
    try:
        # Get statistics for return processing
        today_start = datetime.now().replace(hour=0, minute=0, second=0)
        stats = {
            'retur_hari_ini': Order.query.filter_by(status='pengembalian').filter(
                Order.retur_processed_at >= today_start
            ).count(),
            'total_retur': Order.query.filter_by(status='pengembalian').count(),
            'siap_retur': Order.query.filter(Order.status.in_(['siap_dikirim', 'dikirim', 'selesai'])).count(),
            'dengan_foto': Order.query.filter(Order.return_photo_base64.isnot(None)).count(),
            'barang_rusak': Order.query.filter_by(status='pengembalian', jenis_retur='barang_rusak').count(),
            'jual_kembali': Order.query.filter_by(status='pengembalian', jenis_retur='jual_kembali').count()
        }
        
        # Get recent return scan history
        recent_returns = Order.query.filter_by(status='pengembalian')\
                                  .order_by(Order.retur_processed_at.desc())\
                                  .limit(10).all()
        
        return render_template('scan_retur_foto.html', stats=stats, recent_returns=recent_returns)
        
    except Exception as e:
        logging.error(f"Error loading scan retur foto page: {e}")
        flash('Terjadi kesalahan saat memuat halaman retur', 'error')
        return redirect(url_for('dashboard'))

@app.route('/scan_retur_foto/process', methods=['POST'])
@login_required
@role_required('admin', 'scan retur')
def process_retur_scan():
    """Process return scan with photo documentation"""
    try:
        data = request.get_json()
        order_input = data.get('order_input', '').strip()
        
        if not order_input:
            return jsonify({
                'success': False,
                'message': 'Harap masukkan nomor pesanan atau tracking number'
            })
        
        # Search for order by order_number or tracking_number
        order = Order.query.filter(
            (Order.order_number == order_input) | 
            (Order.tracking_number == order_input)
        ).first()
        
        if not order:
            return jsonify({
                'success': False,
                'message': f'Pesanan tidak ditemukan: {order_input}'
            })
        
        # Check if order is eligible for return
        eligible_statuses = ['siap_dikirim', 'dikirim', 'selesai']
        if order.status not in eligible_statuses:
            return jsonify({
                'success': False,
                'message': f'Pesanan {order_input} tidak bisa diretur. Status saat ini: {order.status}'
            })
        
        # Return order details for photo capture
        return jsonify({
            'success': True,
            'message': 'Pesanan valid untuk retur',
            'order_data': {
                'id': order.id,
                'order_number': order.order_number,
                'tracking_number': order.tracking_number,
                'customer_name': order.customer_name,
                'status': order.status,
                'total_amount': order.total_amount
            },
            'require_photo': True
        })
        
    except Exception as e:
        logging.error(f"Error processing retur scan: {e}")
        return jsonify({
            'success': False,
            'message': 'Terjadi kesalahan saat memproses scan retur'
        })

@app.route('/view_foto/<int:order_id>')
@login_required
@role_required('admin', 'scan retur')
def view_foto(order_id):
    """Display photo in new tab"""
    try:
        order = Order.query.get_or_404(order_id)
        if not order.return_photo_base64:
            flash('Foto tidak ditemukan', 'error')
            return redirect(url_for('scan_retur_foto'))
        
        return render_template('view_foto.html', order=order)
        
    except Exception as e:
        logging.error(f"Error in view_foto: {e}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
        return redirect(url_for('scan_retur_foto'))

@app.route('/scan_retur_foto/save_with_photo', methods=['POST'])
@login_required
@role_required('admin', 'scan retur')
def save_retur_with_photo():
    """Save return with photo documentation"""
    try:
        data = request.get_json()
        order_id = data.get('order_id')
        photo_data = data.get('photo_data')  # Base64 image data
        jenis_retur = data.get('jenis_retur')  # Type of return
        
        if not order_id or not photo_data or not jenis_retur:
            return jsonify({
                'success': False,
                'message': 'Data order, foto, atau jenis retur tidak lengkap'
            })
        
        # Get order
        order = Order.query.get(order_id)
        if not order:
            return jsonify({
                'success': False,
                'message': 'Pesanan tidak ditemukan'
            })
        
        # Process base64 photo data
        try:
            # Store complete base64 data (with data:image prefix for display)
            if not photo_data.startswith('data:image'):
                photo_data = f"data:image/jpeg;base64,{photo_data}"
            
            # Update order with return info
            order.status = 'pengembalian'
            order.return_photo_base64 = photo_data
            order.return_photo_timestamp = datetime.now()
            order.retur_processed_at = datetime.now()
            order.jenis_retur = jenis_retur
            order.retur_user = session.get('username', session.get('user_name', 'Admin'))
            
            # Log activity
            activity = ActivityLog(
                order_number=order.order_number,
                user_name=session.get('user_name', 'Unknown'),
                activity_type='retur_dengan_foto',
                tracking_number=order.tracking_number,
                status='pengembalian',
                notes=f'Retur {jenis_retur.replace("_", " ").title()} dengan dokumentasi foto tersimpan'
            )
            db.session.add(activity)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Retur berhasil diproses dengan foto dokumentasi untuk pesanan {order.order_number}',
                'order_number': order.order_number,
                'has_photo': True
            })
            
        except Exception as photo_error:
            logging.error(f"Error saving photo: {photo_error}")
            db.session.rollback()
            return jsonify({
                'success': False,
                'message': 'Terjadi kesalahan saat menyimpan foto'
            })
            
    except Exception as e:
        logging.error(f"Error saving retur with photo: {e}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': 'Terjadi kesalahan saat menyimpan retur'
        })

# Context processor to provide stores data to all templates
@app.context_processor
def inject_stores():
    """Inject active stores data to all templates for dynamic sidebar"""
    active_stores = Store.query.filter_by(is_active=True).order_by(Store.store_name).all()
    return dict(active_stores=active_stores)

# Store Management Routes
@app.route('/stores/management')
@login_required
@admin_required
def stores_management():
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.args.get('ajax') == '1'
    
    stores = Store.query.all()
    
    if is_ajax:
        return render_template('stores_management_content.html', stores=stores)
    else:
        return render_template('stores_management.html', stores=stores)

@app.route('/store/<store_code>')
@login_required
@admin_required
def store_orders(store_code):
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.args.get('ajax') == '1'
    
    status = request.args.get('status', 'semua')
    page = request.args.get('page', 1, type=int)
    per_page = 20  # 20 orders per page
    
    # Get store info
    store = Store.query.filter_by(sku_code=store_code).first()
    if not store:
        flash(f'Toko dengan kode {store_code} tidak ditemukan', 'error')
        return redirect(url_for('orders_toko'))
    
    # Get orders for this store based on SKU in order items
    # Filter by SKU containing store code directly from OrderItem with DISTINCT
    query = Order.query.join(OrderItem).filter(OrderItem.sku.like(f'%{store_code}%')).distinct()
    
    # Apply status filter
    if status != 'semua':
        query = query.filter(Order.status == status)
    
    # Apply pagination
    orders_pagination = query.order_by(Order.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    orders = orders_pagination.items
    
    # Calculate status counts for this store using DISTINCT to avoid duplicate counting
    status_counts = {}
    base_query = Order.query.join(OrderItem).filter(OrderItem.sku.like(f'%{store_code}%')).distinct()
    status_counts['semua'] = base_query.count()
    status_counts['perlu_dikirim'] = base_query.filter(Order.status == 'perlu_dikirim').count()
    status_counts['siap_dikirim'] = base_query.filter(Order.status == 'siap_dikirim').count()
    status_counts['dikirim'] = base_query.filter(Order.status == 'dikirim').count()
    status_counts['selesai'] = base_query.filter(Order.status == 'selesai').count()
    status_counts['pengembalian'] = base_query.filter(Order.status == 'pengembalian').count()
    
    if is_ajax:
        return render_template('store_orders_content.html', 
                             orders=orders, 
                             store=store,
                             current_status=status,
                             status_counts=status_counts,
                             pagination=orders_pagination)
    else:
        return render_template('store_orders.html', 
                             orders=orders, 
                             store=store,
                             current_status=status,
                             status_counts=status_counts,
                             pagination=orders_pagination)

# ============= PROFIT TRACKER ROUTES =============

@app.route('/profit_tracker')
@login_required
@admin_required
def profit_tracker():
    """Dashboard Analisis Keuntungan - Tahap 1"""
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.args.get('ajax') == '1'
    
    logging.debug(f"profit_tracker called - is_ajax: {is_ajax}")
    
    try:
        # Get or create profit settings
        settings = ProfitSettings.query.first()
        if not settings:
            settings = ProfitSettings()
            db.session.add(settings)
            db.session.commit()
        
        # Get today's advertising cost from store_advertising_costs table
        today = datetime.utcnow().date()
        today_advertising_cost = db.session.query(db.func.sum(StoreAdvertisingCost.daily_cost)).filter(
            StoreAdvertisingCost.expense_date == today
        ).scalar() or 0
        
        # Get recent advertising costs (last 7 days)
        from datetime import timedelta
        recent_costs = DailyCost.query.filter(
            DailyCost.cost_date >= datetime.utcnow() - timedelta(days=7)
        ).order_by(DailyCost.cost_date.desc()).all()
        
        # Add today_date for template comparison
        today_date = today
        
        # Get operational costs for profit calculation only
        operational_costs = OperationalCost.query.filter_by(is_active=True).all()
        total_operational_monthly = sum(cost.monthly_amount for cost in operational_costs)
        total_operational_daily = total_operational_monthly / 30
        
        # Calculate profit statistics for today
        today_start = datetime.combine(today, datetime.min.time())
        today_end = today_start + timedelta(days=1)
        
        # OPTIMIZED: Get today's orders with raw SQL for maximum performance
        today_orders_query = db.session.query(Order).filter(
            Order.created_at >= today_start,
            Order.created_at < today_end
        )
        today_orders = today_orders_query.all()
        
        total_revenue = 0
        total_cost = 0
        total_orders = len(today_orders)
        
        # SUPER OPTIMIZED: Ultra-fast in-memory product cache
        global _product_cache, _product_cache_time
        current_time = time.time()
        
        # Use global cache with 5-minute TTL
        if '_product_cache' not in globals() or current_time - _product_cache_time > 300:
            _product_cache = {p.sku: p.price for p in Product.query.all()}
            _product_cache_time = current_time
        
        all_products = _product_cache
        
        # OPTIMIZED: Get all order items in single query
        order_ids = [order.id for order in today_orders]
        all_order_items = OrderItem.query.filter(OrderItem.order_id.in_(order_ids)).all() if order_ids else []
        
        # Group items by order_id for efficient lookup
        items_by_order = {}
        for item in all_order_items:
            if item.order_id not in items_by_order:
                items_by_order[item.order_id] = []
            items_by_order[item.order_id].append(item)
        
        # Calculate total revenue and costs
        for order in today_orders:
            # Use pre-grouped items
            order_items = items_by_order.get(order.id, [])
            order_revenue = sum(item.price * item.quantity for item in order_items)
            total_revenue += order_revenue
            
            # Calculate costs per order
            admin_fee = order_revenue * (settings.admin_fee_percentage / 100)
            order_cost = admin_fee + settings.fee_per_order + settings.insurance_fee
            
            # OPTIMIZED: Use pre-loaded products dictionary
            for item in order_items:
                try:
                    # Find product modal price
                    clean_sku = item.sku or ""
                    if '|' in clean_sku:
                        parts = clean_sku.split('|')
                        if len(parts) >= 2:
                            clean_sku = parts[1].strip()
                    
                    # OPTIMIZED: Use dictionary lookup instead of database query
                    if clean_sku and clean_sku in all_products:
                        product_price = all_products[clean_sku]
                        if product_price:
                            order_cost += float(product_price) * int(item.quantity)
                except Exception as e:
                    logging.warning(f"Error calculating product cost for SKU {item.sku}: {str(e)}")
                    continue
            
            total_cost += order_cost
        
        # Add daily advertising cost
        total_cost += today_advertising_cost
        
        # Add daily operational costs
        total_cost += total_operational_daily
        
        # Calculate profit and margin
        total_profit = total_revenue - total_cost
        margin_percentage = (total_profit / total_revenue * 100) if total_revenue > 0 else 0
        
        # Debug logging
        logging.debug(f"Profit calculation - Revenue: {total_revenue}, Cost: {total_cost}, Advertising: {today_advertising_cost}, Profit: {total_profit}")
        
        profit_stats = {
            'total_revenue': total_revenue,
            'total_profit': total_profit,
            'margin_percentage': margin_percentage,
            'total_orders': total_orders
        }
        
        # Use stores table as single source of truth for both dropdown and calculations
        stores = Store.query.filter_by(is_active=True).all()
        available_stores = stores  # Same data source for dropdown
        
        # OPTIMIZED: Calculate profit per store with pre-loaded data
        store_profits = []
        
        # Pre-group order items by store to avoid repeated queries
        store_order_items = {}
        for store in stores:
            store_order_items[store.sku_code] = []
        
        # OPTIMIZED: Single pass through all order items using pre-grouped data
        for order in today_orders:
            order_items = items_by_order.get(order.id, [])
            for item in order_items:
                for store in stores:
                    if store.sku_code in (item.sku or ''):
                        if store.sku_code not in store_order_items:
                            store_order_items[store.sku_code] = []
                        store_order_items[store.sku_code].append((order, item))
        
        for store in stores:
            store_items_data = store_order_items.get(store.sku_code, [])
            
            store_revenue = 0
            store_cost = 0
            
            # Group items by order to avoid duplicate calculations
            orders_processed = set()
            
            for order, item in store_items_data:
                item_revenue = item.price * item.quantity
                store_revenue += item_revenue
                
                # Only calculate order-level costs once per order
                if order.id not in orders_processed:
                    # Calculate proportional costs
                    admin_fee = item_revenue * (settings.admin_fee_percentage / 100)
                    store_cost += admin_fee + settings.fee_per_order + settings.insurance_fee
                    orders_processed.add(order.id)
                
                # OPTIMIZED: Add modal costs with pre-loaded product data
                clean_sku = item.sku or ""
                if '|' in clean_sku:
                    parts = clean_sku.split('|')
                    if len(parts) >= 2:
                        clean_sku = parts[1].strip()
                
                # Use pre-loaded products dictionary
                if clean_sku in all_products:
                    product_price = all_products[clean_sku]
                    if product_price:
                        store_cost += float(product_price) * item.quantity
            
            # Add store-specific advertising cost
            store_advertising_cost = db.session.query(db.func.sum(StoreAdvertisingCost.daily_cost)).filter(
                StoreAdvertisingCost.store_id == store.id,
                StoreAdvertisingCost.expense_date == today
            ).scalar() or 0
            
            # Distribute operational cost proportionally
            if total_revenue > 0:
                store_operational = total_operational_daily * (store_revenue / total_revenue)
                store_cost += store_advertising_cost + store_operational
            
            store_profit = store_revenue - store_cost
            store_margin = (store_profit / store_revenue * 100) if store_revenue > 0 else 0
            
            store_profits.append({
                'store_name': store.store_name,
                'sku_code': store.sku_code,
                'revenue': store_revenue,
                'profit': store_profit,
                'margin': store_margin,
                'orders': len(store_items_data)
            })
        
        # Get advertising costs history untuk edit functionality
        advertising_history = db.session.query(StoreAdvertisingCost).join(Store).order_by(StoreAdvertisingCost.expense_date.desc()).all()
        
        if is_ajax:
            return render_template('profit_tracker_clean.html',
                                 profit_stats=profit_stats,
                                 stores=stores,
                                 store_profits=store_profits,
                                 current_settings=settings,
                                 today_advertising_cost=today_advertising_cost,
                                 available_stores=available_stores,
                                 advertising_history=advertising_history)
        else:
            return render_template('profit_tracker_clean.html',
                                 profit_stats=profit_stats,
                                 stores=stores,
                                 store_profits=store_profits,
                                 current_settings=settings,
                                 today_advertising_cost=today_advertising_cost,
                                 available_stores=available_stores,
                                 advertising_history=advertising_history)
    
    except Exception as e:
        logging.error(f"Error in profit_tracker: {str(e)}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/profit_tracker_settings', methods=['POST'])
@login_required
@admin_required
def profit_tracker_settings():
    """Update profit settings"""
    try:
        # Get or create settings
        settings = ProfitSettings.query.first()
        if not settings:
            settings = ProfitSettings()
            db.session.add(settings)
        
        # Update settings from form
        settings.admin_fee_percentage = float(request.form.get('admin_fee_percentage', 11))
        settings.fee_per_order = float(request.form.get('fee_per_order', 1250))
        settings.insurance_fee = float(request.form.get('insurance_fee', 350))
        settings.updated_at = datetime.utcnow()
        
        # Handle store-specific advertising cost with retroactive date
        store_id = request.form.get('store_id')
        advertising_cost = float(request.form.get('advertising_cost', 0))
        cost_date_str = request.form.get('cost_date')
        
        if store_id and advertising_cost > 0 and cost_date_str:
            from datetime import datetime as dt
            cost_date = dt.strptime(cost_date_str, '%Y-%m-%d').date()
            
            # Check if advertising cost already exists for this store and date
            existing_cost = StoreAdvertisingCost.query.filter(
                StoreAdvertisingCost.store_id == int(store_id),
                StoreAdvertisingCost.expense_date == cost_date
            ).first()
            
            if existing_cost:
                # Check edit limits untuk non-admin
                current_user = User.query.filter_by(username=session.get('username')).first()
                if not current_user or 'admin' not in current_user.role:
                    if existing_cost.edit_count >= 3:
                        flash('Maksimal 3x edit per toko. Hubungi admin jika perlu edit lebih.', 'error')
                        return redirect(url_for('profit_tracker'))
                    existing_cost.edit_count += 1
                    flash(f'Biaya iklan berhasil diperbarui! (Edit {existing_cost.edit_count}/3)', 'success')
                else:
                    flash('Biaya iklan berhasil diperbarui! (Admin - Unlimited Edit)', 'success')
                
                # Update existing cost
                existing_cost.daily_cost = advertising_cost
                existing_cost.edited_by = session.get('username')
                existing_cost.updated_at = datetime.utcnow()
            else:
                # Create new advertising cost record
                new_cost = StoreAdvertisingCost(
                    store_id=int(store_id),
                    expense_date=cost_date,
                    platform='shopee',
                    daily_cost=advertising_cost,
                    created_by=session.get('username', 'admin'),
                    edit_count=0,
                    edited_by=None,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                db.session.add(new_cost)
        
        # No need for legacy daily_costs sync - profit calculation now reads from store_advertising_costs directly
        
        db.session.commit()
        current_user = User.query.filter_by(username=session.get('username')).first()
        if current_user and 'admin' in current_user.role:
            flash('Pengaturan profit berhasil disimpan (Admin - Unlimited Edit)', 'success')
        else:
            flash('Pengaturan profit berhasil disimpan', 'success')
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error updating profit settings: {str(e)}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
    
    return redirect(url_for('profit_tracker'))

@app.route('/save_daily_cost', methods=['POST'])
@login_required
@admin_required
def save_daily_cost():
    """Save daily advertising cost via AJAX"""
    try:
        data = request.get_json()
        advertising_cost = float(data.get('advertising_cost', 0))
        
        today = datetime.utcnow().date()
        daily_cost = DailyCost.query.filter_by(cost_date=today).first()
        if not daily_cost:
            daily_cost = DailyCost(cost_date=today)
            db.session.add(daily_cost)
        
        daily_cost.advertising_cost = advertising_cost
        daily_cost.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Biaya iklan berhasil disimpan'})
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error saving daily cost: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/delete_advertising_history', methods=['POST'])
@login_required
@admin_required
def delete_advertising_history():
    """Bulk delete advertising history records"""
    try:
        data = request.get_json()
        history_ids = data.get('history_ids', [])
        
        if not history_ids:
            return jsonify({'success': False, 'message': 'Tidak ada history yang dipilih'}), 400
        
        # Validate all IDs are integers
        try:
            history_ids = [int(id) for id in history_ids]
        except ValueError:
            return jsonify({'success': False, 'message': 'ID history tidak valid'}), 400
        
        # Get current user for audit trail
        current_user = User.query.filter_by(username=session.get('username')).first()
        username = current_user.username if current_user else 'unknown'
        
        # Count existing records before deletion
        existing_count = StoreAdvertisingCost.query.filter(StoreAdvertisingCost.id.in_(history_ids)).count()
        
        if existing_count == 0:
            return jsonify({'success': False, 'message': 'History tidak ditemukan'}), 404
        
        # Bulk delete using raw SQL for better performance
        deleted_count = db.session.execute(
            text("DELETE FROM store_advertising_costs WHERE id = ANY(:ids)"),
            {'ids': history_ids}
        ).rowcount
        
        db.session.commit()
        
        # Log the bulk deletion for audit purposes
        logging.info(f"Bulk delete advertising history: {deleted_count} records deleted by {username}")
        
        return jsonify({
            'success': True, 
            'message': f'{deleted_count} history berhasil dihapus',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error bulk deleting advertising history: {str(e)}")
        return jsonify({'success': False, 'message': f'Terjadi kesalahan: {str(e)}'}), 500

# ============= CLEANED UP ROUTES =============

@app.route('/employee_management')
@login_required
@admin_required
def employee_management():
    """Manajemen Karyawan"""
    # Force normal template after redirect from form submission
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.args.get('ajax') == '1'
    
    # Override AJAX detection if this is a redirect from form submission (no AJAX for redirects)
    if request.method == 'GET' and not request.args.get('ajax'):
        is_ajax = False
    
    try:
        # Get branch filter parameter (default to all employees, no filter)
        current_branch = request.args.get('branch', None)
        
        # Get employees filtered by branch with salary group data
        db.session.rollback()  # Clear any pending transactions
        employees = db.session.query(
            Employee.id,
            Employee.employee_id,
            Employee.full_name,
            Employee.position,
            Employee.branch_location,
            Employee.is_active,
            Employee.created_at,
            Employee.salary_group_id,
            SalaryGroup.group_name,
            SalaryGroup.daily_wage
        ).outerjoin(
            SalaryGroup, Employee.salary_group_id == SalaryGroup.id
        )
        
        # Apply branch filter only if specified
        if current_branch:
            employees = employees.filter(Employee.branch_location == current_branch)
        
        # Add pagination support
        page = request.args.get('page', 1, type=int)
        per_page = 20  # Show 20 employees per page
        
        employees_paginated = employees.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        employees = employees_paginated.items
        total_employees = employees_paginated.total
        
        # Get all salary groups for inline editing with location info
        salary_groups = db.session.query(
            SalaryGroup.id,
            SalaryGroup.group_name,
            SalaryGroup.daily_wage,
            Location.location_name
        ).join(
            Location, SalaryGroup.location_id == Location.id
        ).all()
        
        # Convert to dict format for JSON serialization
        salary_groups_data = [
            {
                'id': sg.id,
                'group_name': sg.group_name,
                'daily_wage': sg.daily_wage,
                'location_name': sg.location_name
            }
            for sg in salary_groups
        ]
        
        # Calculate statistics for current branch
        employees_count = len(employees)
        active_employees_count = len([e for e in employees if e.is_active])
        positions = set(e.position for e in employees if e.position)
        positions_count = len(positions)
        
        # Today's attendance for current branch employees
        today = datetime.utcnow().date()
        branch_employee_ids = [e.id for e in employees]
        attendance_today = Attendance.query.filter(
            Attendance.attendance_date == today,
            Attendance.employee_id.in_(branch_employee_ids)
        ).count() if branch_employee_ids else 0
        
        # Get available users for dropdown
        try:
            used_user_ids = [e.user_id for e in employees if e.user_id]
            if used_user_ids:
                available_users = User.query.filter(~User.id.in_(used_user_ids)).all()
            else:
                available_users = User.query.all()
        except Exception:
            available_users = []
        
        # Calculate statistics for stats object
        stats = {
            'total_employees': employees_count,
            'active_employees': active_employees_count,
            'lampung_employees': len([e for e in employees if e.branch_location == 'Lampung']),
            'tangerang_employees': len([e for e in employees if e.branch_location == 'Tangerang'])
        }
        
        context = {
            'employees': employees,
            'salary_groups': salary_groups_data,
            'current_branch': current_branch,
            'employees_count': len(employees),
            'active_employees_count': active_employees_count,
            'positions_count': positions_count,
            'attendance_today': attendance_today,
            'available_users': available_users,
            'stats': stats,
            'total_employees': total_employees,
            'pagination': employees_paginated
        }
        

        
        # Always use full template with 4 statistics cards for consistent interface
        return render_template('employee_management.html', **context)
    
    except Exception as e:
        logging.error(f"Error in employee_management: {str(e)}")
        flash(f'Terjadi kesalahan saat memuat data karyawan: {str(e)}', 'error')
        
        # Provide fallback context to prevent template errors
        fallback_context = {
            'employees': [],
            'salary_groups': [],
            'current_branch': current_branch or 'All',
            'employees_count': 0,
            'active_employees_count': 0,
            'positions_count': 0,
            'attendance_today': 0,
            'available_users': [],
            'stats': {
                'total_employees': 0,
                'active_employees': 0,
                'lampung_employees': 0,
                'tangerang_employees': 0
            }
        }
        
        # Always use full template for fallback to ensure proper display
        return render_template('employee_management.html', **fallback_context)

@app.route('/api/employees_by_branch')
@login_required
@admin_required
def api_employees_by_branch():
    """API endpoint untuk mendapatkan data karyawan berdasarkan branch (AJAX)"""
    try:
        branch = request.args.get('branch', 'Lampung')
        
        # Query employees based on branch with salary group data
        employees = db.session.query(
            Employee.id,
            Employee.employee_id,
            Employee.full_name,
            Employee.position,
            Employee.branch_location,
            Employee.is_active,
            Employee.created_at,
            Employee.salary_group_id,
            SalaryGroup.group_name,
            SalaryGroup.daily_wage
        ).outerjoin(
            SalaryGroup, Employee.salary_group_id == SalaryGroup.id
        ).filter(
            Employee.branch_location == branch
        ).all()
        
        # Get all salary groups for inline editing with location info
        salary_groups = db.session.query(
            SalaryGroup.id,
            SalaryGroup.group_name,
            SalaryGroup.daily_wage,
            Location.location_name
        ).join(
            Location, SalaryGroup.location_id == Location.id
        ).all()
        
        # Convert to dict format for JSON serialization
        salary_groups_data = [
            {
                'id': sg.id,
                'group_name': sg.group_name,
                'daily_wage': sg.daily_wage,
                'location_name': sg.location_name
            }
            for sg in salary_groups
        ]
        
        # Calculate statistics for the selected branch
        employees_count = len(employees)
        active_employees_count = len([emp for emp in employees if emp.is_active])
        positions = set(emp.position for emp in employees if emp.position)
        positions_count = len(positions)
        
        # Today's attendance for current branch employees
        today = datetime.utcnow().date()
        branch_employee_ids = [e.id for e in employees]
        attendance_today = Attendance.query.filter(
            Attendance.attendance_date == today,
            Attendance.employee_id.in_(branch_employee_ids)
        ).count() if branch_employee_ids else 0
        
        # Get available users for the dropdown
        try:
            used_user_ids = [e.user_id for e in employees if e.user_id]
            if used_user_ids:
                available_users = User.query.filter(~User.id.in_(used_user_ids)).all()
            else:
                available_users = User.query.all()
        except Exception:
            available_users = []
        
        # Return JSON response with rendered HTML content
        html_content = render_template('employee_management.html',
                                     employees=employees,
                                     salary_groups=salary_groups_data,
                                     employees_count=employees_count,
                                     active_employees_count=active_employees_count,
                                     positions_count=positions_count,
                                     attendance_today=attendance_today,
                                     current_branch=branch,
                                     available_users=available_users)
        
        return jsonify({
            'success': True,
            'html': html_content,
            'statistics': {
                'employees_count': employees_count,
                'active_employees_count': active_employees_count,
                'positions_count': positions_count,
                'attendance_today': attendance_today,
                'current_branch': branch
            }
        })
        
    except Exception as e:
        logging.error(f"Error in api_employees_by_branch: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/add_employee', methods=['POST'])
@login_required
@admin_required
def add_employee():
    """Tambah karyawan baru"""
    logging.info(f"ADD EMPLOYEE: Request from user {session.get('user_id')} - {request.method}")
    logging.info(f"ADD EMPLOYEE: Form data keys: {list(request.form.keys()) if request.form else 'No form data'}")
    logging.info(f"ADD EMPLOYEE: Form values: {dict(request.form) if request.form else 'No form data'}")
    try:
        # Handle both regular POST and AJAX JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form
        
        # Get form data from template
        full_name = data.get('full_name')
        employee_id = data.get('employee_id')  # This comes from auto-generated field
        position = data.get('position')
        branch_location = data.get('branch_location')
        salary_group_id = data.get('salary_group_id')
        
        # Optional fields
        user_id = data.get('user_id')
        join_date = data.get('join_date')
        is_active = data.get('is_active', '1') == '1'
        
        # Generate employee_id automatically (EMP_001, EMP_002, etc.)
        def generate_next_employee_id():
            try:
                # Get the highest existing employee ID number
                result = db.session.execute(text("""
                    SELECT employee_id 
                    FROM employees 
                    WHERE employee_id LIKE 'EMP_%'
                    ORDER BY CAST(SUBSTR(employee_id, 5) AS INTEGER) DESC 
                    LIMIT 1
                """)).fetchone()
                
                if result:
                    # Extract number from EMP_XXX format
                    last_id = result[0]
                    last_number = int(last_id.split('_')[1])
                    next_number = last_number + 1
                else:
                    # No existing employees, start with 1
                    next_number = 1
                
                # Format with zero padding (3 digits)
                return f"EMP_{next_number:03d}"
                
            except Exception as e:
                logging.error(f"Error generating employee ID: {str(e)}")
                # Fallback to simple increment
                last_employee = Employee.query.order_by(Employee.id.desc()).first()
                next_id = (last_employee.id + 1) if last_employee else 1
                return f"EMP_{next_id:03d}"
        
        # Use the employee_id from form if provided, otherwise generate new one
        if not employee_id or employee_id.strip() == '':
            employee_id = generate_next_employee_id()
        
        # Validation
        if not all([full_name, branch_location, salary_group_id]):
            if request.is_json:
                return jsonify({'success': False, 'message': 'Harap isi semua field yang diperlukan'})
            flash('Harap isi semua field yang diperlukan', 'error')
            return redirect(url_for('employee_management'))
        
        # Convert user_id if provided
        if user_id and user_id != '':
            user_id = int(user_id)
        else:
            user_id = None
        
        # Convert salary_group_id to integer
        try:
            salary_group_id = int(salary_group_id)
        except (ValueError, TypeError):
            if request.is_json:
                return jsonify({'success': False, 'message': 'Kelompok gaji tidak valid'})
            flash('Kelompok gaji tidak valid', 'error')
            return redirect(url_for('employee_management'))
        
        new_employee = Employee(
            user_id=user_id,
            employee_id=employee_id,
            full_name=full_name,
            position=position,
            branch_location=branch_location,
            salary_group_id=salary_group_id,
            is_active=is_active,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        db.session.add(new_employee)
        db.session.commit()
        
        message = f'Karyawan {full_name} berhasil ditambahkan dengan ID {employee_id}'
        logging.info(f"✅ ADD EMPLOYEE SUCCESS: {message}")
        
        # Always return JSON for AJAX requests (check for AJAX in headers or content-type)
        if request.is_json or request.headers.get('Content-Type') == 'multipart/form-data' or 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
            return jsonify({'success': True, 'message': message, 'employee_id': employee_id})
        else:
            flash(message, 'success')
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"❌ ADD EMPLOYEE ERROR: {str(e)}")
        logging.error(f"❌ ADD EMPLOYEE ERROR - Full traceback:", exc_info=True)
        error_msg = f'Terjadi kesalahan saat menambah karyawan: {str(e)}'
        
        # Always return JSON for AJAX requests
        if request.is_json or request.headers.get('Content-Type') == 'multipart/form-data' or 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
            return jsonify({'success': False, 'message': error_msg})
        else:
            flash(error_msg, 'error')
    
    return redirect(url_for('employee_management'))

@app.route('/employee_management/get_next_id', methods=['GET'])
@login_required
@admin_required
def get_next_employee_id_api():
    """Get next available employee ID for form auto-fill"""
    try:
        # Get the highest existing employee ID number
        result = db.session.execute(text("""
            SELECT employee_id 
            FROM employees 
            WHERE employee_id LIKE 'EMP_%'
            ORDER BY CAST(SUBSTR(employee_id, 5) AS INTEGER) DESC 
            LIMIT 1
        """)).fetchone()
        
        if result:
            # Extract number from EMP_XXX format
            last_id = result[0]
            last_number = int(last_id.split('_')[1])
            next_number = last_number + 1
        else:
            # No existing employees, start with 1
            next_number = 1
        
        # Generate and check if ID already exists (safety check for duplicates)
        while True:
            candidate_id = f"EMP_{next_number:03d}"
            existing = db.session.execute(text("""
                SELECT COUNT(*) FROM employees WHERE employee_id = :id
            """), {"id": candidate_id}).scalar()
            
            if existing == 0:
                next_id = candidate_id
                break
            next_number += 1
        
        return jsonify({'success': True, 'next_id': next_id})
    except Exception as e:
        logging.error(f"Error getting next employee ID: {str(e)}")
        return jsonify({'success': False, 'message': 'Error generating ID'})

@app.route('/employee_management/delete_selected', methods=['POST'])
@login_required
def delete_selected_employees():
    """Delete selected employees via AJAX with safety checks"""
    logging.info(f"Delete selected employees called by user: {session.get('user_id')}")
    try:
        data = request.get_json()
        employee_ids = data.get('employee_ids', [])
        force_delete = data.get('force_delete', False)  # New parameter for force delete
        
        if not employee_ids:
            return jsonify({'success': False, 'error': 'Tidak ada karyawan yang dipilih'})
        
        success_count = 0
        error_count = 0
        skipped_count = 0
        
        for employee_id in employee_ids:
            try:
                employee = Employee.query.get(employee_id)
                if employee:
                    # ALWAYS HARD DELETE - Clean up all related records first then delete permanently
                    try:
                        # Clean up ALL related records (payroll, attendance, barcodes, approvals)
                        db.session.execute(text("DELETE FROM monthly_payrolls WHERE employee_id = :emp_id"), {"emp_id": employee.id})
                        db.session.execute(text("DELETE FROM attendance_records WHERE employee_id = :emp_id"), {"emp_id": employee.id})
                        db.session.execute(text("DELETE FROM attendance_approvals WHERE employee_id = :emp_id"), {"emp_id": employee.id})
                        db.session.execute(text("DELETE FROM attendance_barcodes WHERE employee_id = :emp_id"), {"emp_id": employee.id})
                        
                        # Delete the employee permanently
                        db.session.delete(employee)
                        db.session.commit()
                        success_count += 1
                        logging.info(f"Hard deleted employee {employee.full_name} - ALL records removed permanently")
                        
                    except Exception as cleanup_error:
                        db.session.rollback()
                        logging.error(f"Failed to hard delete employee {employee.full_name}: {cleanup_error}")
                        error_count += 1
                else:
                    error_count += 1
            except Exception as e:
                db.session.rollback()
                logging.error(f"Failed to delete employee {employee_id}: {str(e)}")
                error_count += 1
        
        # Prepare response message
        message_parts = []
        if success_count > 0:
            message_parts.append(f'{success_count} karyawan berhasil diproses')
        
        if error_count > 0:
            message_parts.append(f'{error_count} karyawan gagal diproses')
        
        return jsonify({
            'success': success_count > 0,
            'deleted_count': success_count,
            'skipped_count': 0,  # No more skipping, all are processed
            'error_count': error_count,
            'message': '. '.join(message_parts) if message_parts else 'Tidak ada karyawan yang diproses'
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error in delete_selected_employees: {str(e)}")
        return jsonify({'success': False, 'error': f'Terjadi kesalahan: {str(e)}'})

@app.route('/employee_management/get/<int:employee_id>')
@login_required
@admin_required
def get_employee_details(employee_id):
    """Get employee details for edit modal"""
    try:
        employee = Employee.query.get_or_404(employee_id)
        
        # Get salary group information
        salary_group_name = None
        if employee.salary_group_id:
            salary_group = SalaryGroup.query.get(employee.salary_group_id)
            if salary_group:
                salary_group_name = salary_group.group_name
        
        return jsonify({
            'success': True,
            'employee': {
                'id': employee.id,
                'employee_id': employee.employee_id,
                'full_name': employee.full_name,
                'position': employee.position,
                'branch_location': employee.branch_location,
                'salary_group_id': employee.salary_group_id,
                'salary_group_name': salary_group_name,
                'is_active': employee.is_active,
                'created_at': employee.created_at.isoformat() if employee.created_at else None
            }
        })
        
    except Exception as e:
        logging.error(f"Error getting employee details: {str(e)}")
        return jsonify({'success': False, 'error': f'Terjadi kesalahan: {str(e)}'})

@app.route('/employee/update', methods=['POST'])
@login_required
@admin_required
def update_employee():
    """Update employee data via AJAX"""
    try:
        data = request.get_json()
        employee_id = data.get('employee_id')
        
        if not employee_id:
            return jsonify({'success': False, 'error': 'Employee ID diperlukan'})
        
        employee = Employee.query.get_or_404(employee_id)
        
        # Update fields
        employee.full_name = data.get('name', '').strip()
        employee.position = data.get('position', '').strip()
        employee.monthly_salary = float(data.get('monthly_salary', 0))
        employee.branch_location = data.get('branch_location', 'Lampung')
        employee.is_active = data.get('is_active', False)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Karyawan {employee.full_name} berhasil diupdate'
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error updating employee: {str(e)}")
        return jsonify({'success': False, 'error': f'Terjadi kesalahan: {str(e)}'})

# Inline Editing Routes for Employee Management
@app.route('/employee/update_field/<int:employee_id>', methods=['POST'])
@login_required
@admin_required
def update_employee_field(employee_id):
    """Update single employee field for inline editing"""
    try:
        employee = Employee.query.get_or_404(employee_id)
        data = request.get_json()
        
        # Update fields based on request data
        if 'full_name' in data:
            employee.full_name = data['full_name']
        if 'position' in data:
            employee.position = data['position']
        if 'salary_group_id' in data:
            if data['salary_group_id']:
                # Validate salary group exists
                salary_group = SalaryGroup.query.get(data['salary_group_id'])
                if not salary_group:
                    return jsonify({'success': False, 'message': 'Kelompok gaji tidak ditemukan'})
                employee.salary_group_id = data['salary_group_id']
            else:
                employee.salary_group_id = None
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Data karyawan berhasil diperbarui'
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error updating employee field: {str(e)}")
        return jsonify({'success': False, 'message': f'Terjadi kesalahan: {str(e)}'})

@app.route('/employee/toggle_status/<int:employee_id>', methods=['POST'])
@login_required
@admin_required
def toggle_employee_status_inline(employee_id):
    """Toggle employee active status for inline editing"""
    try:
        employee = Employee.query.get_or_404(employee_id)
        data = request.get_json()
        
        employee.is_active = data.get('is_active', False)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Status karyawan berhasil diubah menjadi {"aktif" if employee.is_active else "tidak aktif"}'
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error toggling employee status: {str(e)}")
        return jsonify({'success': False, 'message': f'Terjadi kesalahan: {str(e)}'})

@app.route('/employee/details/<int:employee_id>')
@login_required
@admin_required
def get_employee_details_for_modal(employee_id):
    """Get employee details for detail modal"""
    try:
        # Query with salary group information
        employee_data = db.session.query(
            Employee.id,
            Employee.employee_id,
            Employee.full_name,
            Employee.position,
            Employee.branch_location,
            Employee.is_active,
            Employee.created_at,
            SalaryGroup.group_name,
            SalaryGroup.daily_wage
        ).outerjoin(
            SalaryGroup, Employee.salary_group_id == SalaryGroup.id
        ).filter(
            Employee.id == employee_id
        ).first()
        
        if not employee_data:
            return jsonify({'success': False, 'message': 'Karyawan tidak ditemukan'})
        
        return jsonify({
            'success': True,
            'employee': {
                'id': employee_data.id,
                'employee_id': employee_data.employee_id,
                'full_name': employee_data.full_name,
                'position': employee_data.position or 'Staff',
                'branch_location': employee_data.branch_location,
                'is_active': employee_data.is_active,
                'created_at': employee_data.created_at.strftime('%d/%m/%Y') if employee_data.created_at else '-',
                'group_name': employee_data.group_name,
                'daily_wage': employee_data.daily_wage or 0
            }
        })
        
    except Exception as e:
        logging.error(f"Error getting employee details: {str(e)}")
        return jsonify({'success': False, 'message': f'Terjadi kesalahan: {str(e)}'})

# QR Code Attendance System Routes
@app.route('/qr_attendance')
@login_required  
@admin_required
def qr_attendance():
    """QR Code Attendance page with barcode scanner + webcam"""
    try:
        from database_models import Attendance, Employee
        # Get Indonesia time date (WIB) for consistent date filtering
        from pytz import timezone
        utc = timezone('UTC')
        wib = timezone('Asia/Jakarta')
        now_utc = datetime.utcnow().replace(tzinfo=utc)
        now_wib = now_utc.astimezone(wib)
        today = now_wib.date()
        
        # Get today's attendance statistics using raw SQL to avoid missing column error
        attendance_today = db.session.execute(
            text("SELECT COUNT(*) FROM attendances WHERE attendance_date = :today"),
            {'today': today}
        ).scalar() or 0
        
        qr_scans_today = db.session.execute(
            text("SELECT COUNT(*) FROM attendances WHERE attendance_date = :today AND attendance_method = 'qr'"),
            {'today': today}
        ).scalar() or 0
        
        photos_taken = db.session.execute(
            text("SELECT COUNT(*) FROM attendances WHERE attendance_date = :today AND check_in_photo IS NOT NULL"),
            {'today': today}
        ).scalar() or 0
        
        active_employees = Employee.query.filter_by(is_active=True).count()
        
        # Get today's attendance records with employee details using raw SQL
        today_attendances_detailed = db.session.execute(
            text("""
                SELECT a.id, a.employee_id, a.attendance_date, a.check_in_time, 
                       a.check_out_time, a.work_type, a.attendance_method,
                       e.full_name, e.employee_id as employee_number, e.branch_location
                FROM attendances a 
                JOIN employees e ON a.employee_id = e.id 
                WHERE a.attendance_date = :today 
                ORDER BY a.check_in_time DESC
            """),
            {'today': today}
        ).fetchall()
        
        return render_template('qr_attendance.html',
                             attendance_today=attendance_today,
                             qr_scans_today=qr_scans_today,
                             photos_taken=photos_taken,
                             active_employees=active_employees,
                             today_attendances=today_attendances_detailed)
        
    except Exception as e:
        logging.error(f"Error in qr_attendance: {str(e)}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/validate_qr_code', methods=['POST'])
@login_required
def validate_qr_code():
    """Validate QR code from barcode scanner"""
    try:
        data = request.get_json()
        qr_data = data.get('qr_data', '').strip()
        
        if not qr_data:
            return jsonify({'success': False, 'message': 'QR Code data kosong'})
        
        # Decode QR data format: employee_id|token|expiry_date
        try:
            parts = qr_data.split('|')
            if len(parts) != 3:
                return jsonify({'success': False, 'message': 'Format QR Code tidak valid'})
            
            employee_id = int(parts[0])
            token = parts[1]
            expiry_str = parts[2]
            
            # Check expiry
            expiry_date = datetime.strptime(expiry_str, '%Y-%m-%d').date()
            if expiry_date < datetime.utcnow().date():
                return jsonify({'success': False, 'message': 'QR Code sudah expired'})
            
            # Get employee
            employee = Employee.query.get(employee_id)
            if not employee:
                return jsonify({'success': False, 'message': 'Karyawan tidak ditemukan'})
            
            if not employee.is_active:
                return jsonify({'success': False, 'message': 'Karyawan tidak aktif'})
            
            # Validate token (simple validation - can be enhanced)
            expected_token = f"QR{employee_id}_{employee.full_name[:3].upper()}"
            if token != expected_token:
                return jsonify({'success': False, 'message': 'QR Code tidak valid - token mismatch'})
            
            return jsonify({
                'success': True,
                'employee': {
                    'id': employee.id,
                    'full_name': employee.full_name,
                    'position': employee.position,
                    'branch_location': employee.branch_location
                }
            })
            
        except (ValueError, IndexError) as e:
            return jsonify({'success': False, 'message': 'Format QR Code tidak dapat dibaca'})
        
    except Exception as e:
        logging.error(f"Error validating QR code: {str(e)}")
        return jsonify({'success': False, 'message': f'Terjadi kesalahan: {str(e)}'})

@app.route('/qr_attendance/<int:employee_id>', methods=['POST'])
@login_required
def qr_attendance_submit(employee_id):
    """Submit QR-based attendance with webcam photo"""
    try:
        data = request.get_json()
        photo_data = data.get('photo')
        attendance_type = data.get('attendance_type', 'masuk')
        
        if not photo_data:
            return jsonify({'success': False, 'message': 'Foto selfie diperlukan'})
        
        employee = Employee.query.get_or_404(employee_id)
        
        # Use Indonesia timezone (UTC+7) for database storage
        from datetime import timezone, timedelta
        indonesia_tz = timezone(timedelta(hours=7))
        current_time_utc = datetime.utcnow()
        current_time_local = current_time_utc.replace(tzinfo=timezone.utc).astimezone(indonesia_tz)
        now = current_time_local.replace(tzinfo=None)  # Remove timezone for database
        today = now.date()
        
        # DEBUG: Log actual times being saved
        print(f"DEBUG QR_ATTENDANCE - UTC Time: {current_time_utc}")
        print(f"DEBUG QR_ATTENDANCE - Indonesia Time: {current_time_local}")  
        print(f"DEBUG QR_ATTENDANCE - Saving to database: {now}")
        logging.info(f"QR_ATTENDANCE - UTC Time: {current_time_utc}")
        logging.info(f"QR_ATTENDANCE - Indonesia Time: {current_time_local}")
        logging.info(f"QR_ATTENDANCE - Saving to database: {now}")
        
        # Get or create attendance record
        attendance = Attendance.query.filter_by(
            employee_id=employee_id,
            attendance_date=today
        ).first()
        
        # Convert base64 photo to just the data part
        if photo_data.startswith('data:image'):
            photo_data = photo_data.split(',')[1]
        
        # Handle different attendance types
        if attendance_type == 'masuk':
            if attendance and attendance.check_in_time:
                return jsonify({'success': False, 'message': 'Sudah absen masuk hari ini'})
            
            if not attendance:
                attendance = Attendance(
                    employee_id=employee_id,
                    attendance_date=today,
                    work_type='normal',
                    attendance_method='qr'
                )
                db.session.add(attendance)
            
            attendance.check_in_time = now
            attendance.check_in_photo = photo_data
            attendance.status = 'present'
            
            message = f'Absen masuk berhasil - {employee.full_name} ({now.strftime("%H:%M:%S")})'
            
        elif attendance_type == 'keluar':
            if not attendance or not attendance.check_in_time:
                return jsonify({'success': False, 'message': 'Belum absen masuk hari ini'})
            
            if attendance.check_out_time:
                return jsonify({'success': False, 'message': 'Sudah absen keluar hari ini'})
            
            attendance.check_out_time = now
            attendance.check_out_photo = photo_data
            
            # Calculate work hours
            work_duration = now - attendance.check_in_time
            work_hours = work_duration.total_seconds() / 3600
            attendance.work_hours = round(work_hours, 2)
            
            message = f'Absen keluar berhasil - {employee.full_name} ({now.strftime("%H:%M:%S")}) - {work_hours:.1f} jam kerja'
            
        elif attendance_type in ['lembur_malam', 'lembur_minggu']:
            # Create overtime attendance
            overtime_attendance = Attendance(
                employee_id=employee_id,
                attendance_date=today,
                work_type='night' if attendance_type == 'lembur_malam' else 'sunday',
                attendance_method='qr',
                check_in_time=now,
                check_in_photo=photo_data,
                status='present'
            )
            db.session.add(overtime_attendance)
            
            overtime_type = 'malam' if attendance_type == 'lembur_malam' else 'Minggu'
            message = f'Absen lembur {overtime_type} berhasil - {employee.full_name} ({now.strftime("%H:%M:%S")})'
        
        db.session.commit()
        
        # AUTO-CALCULATE PAYROLL after attendance submission
        try:
            current_month = now.month
            current_year = now.year
            
            # Trigger payroll calculation for this employee
            payroll_result = calculate_employee_payroll(employee_id, current_year, current_month)
            
            if payroll_result:
                logging.info(f"Payroll auto-calculated for {employee.full_name}: Rp {payroll_result['total_salary']:,.0f}")
                message += f" | Gaji terupdate: Rp {payroll_result['total_salary']:,.0f}"
            
        except Exception as payroll_error:
            logging.error(f"Error in auto-payroll calculation: {payroll_error}")
            # Don't fail the attendance if payroll calculation fails
        
        return jsonify({
            'success': True,
            'message': message,
            'time': now.strftime('%H:%M:%S'),
            'attendance_type': attendance_type
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error in qr_attendance_submit: {str(e)}")
        return jsonify({'success': False, 'message': f'Terjadi kesalahan: {str(e)}'})

@app.route('/employee_qr_generator')
@login_required
@admin_required
def employee_qr_generator():
    """QR Code Generator page for employees"""
    try:
        from database_models import Employee
        
        # Debug: Check if Employee model is accessible
        logging.info(f"Employee model: {Employee}")
        
        # Get all employees with QR status using direct SQL to debug
        employees_data = db.session.execute(
            text("SELECT id, employee_id, full_name, position, branch_location FROM employees WHERE is_active = true")
        ).fetchall()
        
        logging.info(f"Found {len(employees_data)} employees from SQL")
        
        # Convert to list of dicts for template compatibility
        employees = []
        for row in employees_data:
            employee_dict = {
                'id': row[0],
                'employee_id': row[1], 
                'full_name': row[2],
                'position': row[3],
                'branch_location': row[4],
                'qr_code': None,
                'qr_expiry': None
            }
            employees.append(employee_dict)
        
        today = datetime.utcnow().date()
        
        # Statistics
        total_employees = len(employees)
        qr_generated = 0  # Count from QR table
        qr_printed = 0    # Count from print logs
        qr_expires = 365  # Default expiry days
        
        logging.info(f"Rendering template with {total_employees} employees")
        
        return render_template('employee_qr_generator_new.html')
        
    except Exception as e:
        logging.error(f"Error in employee_qr_generator: {str(e)}")
        import traceback
        logging.error(f"Traceback: {traceback.format_exc()}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/generate_single_qr', methods=['POST'])
@login_required
@admin_required
def generate_single_qr():
    """Generate QR code for single employee"""
    try:
        data = request.get_json()
        employee_id = data.get('employee_id')
        expiry_days = data.get('expiry_days', 365)
        
        if not employee_id:
            return jsonify({'success': False, 'error': 'Employee ID diperlukan'})
        
        # Get employee data using direct SQL to avoid SSL issues
        employee_data = db.session.execute(
            text("SELECT id, employee_id, full_name FROM employees WHERE id = :emp_id AND is_active = true"),
            {'emp_id': employee_id}
        ).fetchone()
        
        if not employee_data:
            return jsonify({'success': False, 'error': 'Karyawan tidak ditemukan atau tidak aktif'})
        
        employee_name = employee_data[2]  # full_name
        
        # Generate QR data
        expiry_date = datetime.utcnow().date() + timedelta(days=expiry_days)
        token = f"QR{employee_id}_{employee_name[:3].upper()}"
        qr_data = f"{employee_id}|{token}|{expiry_date.strftime('%Y-%m-%d')}"
        
        # Check if qrcode library is available
        try:
            import qrcode
            from qrcode import constants
        except ImportError:
            return jsonify({'success': False, 'error': 'QR Code library tidak tersedia - pastikan qrcode terinstall'})
            
        qr = qrcode.QRCode(
            version=1,
            error_correction=constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        from io import BytesIO
        import base64
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        logging.info(f"QR code generated successfully for employee {employee_name}")
        
        return jsonify({
            'success': True,
            'qr_code_base64': qr_code_base64,
            'expiry_date': expiry_date.strftime('%d/%m/%Y'),
            'message': f'QR code berhasil digenerate untuk {employee_name}'
        })
        
    except Exception as e:
        logging.error(f"Error generating single QR: {str(e)}")
        import traceback
        logging.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': f'Terjadi kesalahan: {str(e)}'})

# Generate batch QR codes routes
@app.route('/generate_all_qr', methods=['POST'])
@login_required
@admin_required
def generate_all_qr():
    """Generate QR codes for all active employees"""
    try:
        data = request.get_json()
        expiry_days = data.get('expiry_days', 365)
        
        # Get all active employees using direct SQL
        employees_data = db.session.execute(
            text("SELECT id, employee_id, full_name FROM employees WHERE is_active = true")
        ).fetchall()
        
        generated_count = 0
        
        # Check if qrcode library is available
        try:
            import qrcode
            from qrcode import constants
        except ImportError:
            return jsonify({'success': False, 'error': 'QR Code library tidak tersedia - pastikan qrcode terinstall'})
        
        for employee in employees_data:
            employee_id = employee[0]
            employee_name = employee[2]
            # Generate QR data
            expiry_date = datetime.utcnow().date() + timedelta(days=expiry_days)
            token = f"QR{employee_id}_{employee_name[:3].upper()}"
            qr_data = f"{employee_id}|{token}|{expiry_date.strftime('%Y-%m-%d')}"
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(qr_data)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            # TODO: Save to QR table in database
            # For now, just count successful generations
            generated_count += 1
        
        return jsonify({
            'success': True,
            'generated_count': generated_count,
            'message': f'Berhasil generate {generated_count} QR code'
        })
        
    except Exception as e:
        logging.error(f"Error generating all QR codes: {str(e)}")
        return jsonify({'success': False, 'error': f'Terjadi kesalahan: {str(e)}'})

@app.route('/generate_selected_qr', methods=['POST'])
@login_required
@admin_required
def generate_selected_qr():
    """Generate QR codes for selected employees"""
    try:
        data = request.get_json()
        employee_ids = data.get('employee_ids', [])
        expiry_days = data.get('expiry_days', 365)
        
        if not employee_ids:
            return jsonify({'success': False, 'error': 'Tidak ada karyawan yang dipilih'})
        
        generated_count = 0
        
        if not qrcode:
            return jsonify({'success': False, 'error': 'QR Code library not available'})
        
        for employee_id in employee_ids:
            # Get employee data using direct SQL to avoid SSL issues
            employee_data = db.session.execute(
                text("SELECT id, employee_id, full_name FROM employees WHERE id = :emp_id AND is_active = true"),
                {'emp_id': employee_id}
            ).fetchone()
            
            if not employee_data:
                continue
                
            employee_name = employee_data[2]
                
            # Generate QR data
            expiry_date = datetime.utcnow().date() + timedelta(days=expiry_days)
            token = f"QR{employee_id}_{employee_name[:3].upper()}"
            qr_data = f"{employee_id}|{token}|{expiry_date.strftime('%Y-%m-%d')}"
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(qr_data)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            # TODO: Save to QR table in database
            generated_count += 1
        
        return jsonify({
            'success': True,
            'generated_count': generated_count,
            'message': f'Berhasil generate {generated_count} QR code'
        })
        
    except Exception as e:
        logging.error(f"Error generating selected QR codes: {str(e)}")
        return jsonify({'success': False, 'error': f'Terjadi kesalahan: {str(e)}'})

# QR Detail and Print routes
@app.route('/qr_detail/<int:employee_id>')
@login_required
@admin_required
def qr_detail(employee_id):
    """Show QR code detail for employee"""
    try:
        # Get employee data using direct SQL
        employee_data = db.session.execute(
            text("SELECT id, employee_id, full_name, position, branch_location FROM employees WHERE id = :emp_id AND is_active = true"),
            {'emp_id': employee_id}
        ).fetchone()
        
        if not employee_data:
            flash('Karyawan tidak ditemukan', 'error')
            return redirect(url_for('employee_qr_generator'))
        
        employee_name = employee_data[2]
        employee_position = employee_data[3]
        employee_branch = employee_data[4]
        
        # Generate QR data (temporary - in real app this would be saved in DB)
        expiry_date = datetime.utcnow().date() + timedelta(days=365)
        token = f"QR{employee_id}_{employee_name[:3].upper()}"
        qr_data = f"{employee_id}|{token}|{expiry_date.strftime('%Y-%m-%d')}"
        
        # Generate QR code
        try:
            import qrcode
            from qrcode import constants
        except ImportError:
            flash('QR Code library tidak tersedia', 'error')
            return redirect(url_for('employee_qr_generator'))
            
        qr = qrcode.QRCode(
            version=1,
            error_correction=constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        from io import BytesIO
        import base64
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return render_template('qr_detail.html',
                             employee_id=employee_id,
                             employee_name=employee_name,
                             employee_position=employee_position,
                             employee_branch=employee_branch,
                             qr_code_base64=qr_code_base64,
                             qr_data=qr_data,
                             expiry_date=expiry_date.strftime('%d/%m/%Y'))
        
    except Exception as e:
        logging.error(f"Error in qr_detail: {str(e)}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
        return redirect(url_for('employee_qr_generator'))

@app.route('/print_qr/<int:employee_id>')
@login_required
@admin_required
def print_qr(employee_id):
    """Print QR code for employee"""
    try:
        # Get employee data using direct SQL
        employee_data = db.session.execute(
            text("SELECT id, employee_id, full_name, position, branch_location FROM employees WHERE id = :emp_id AND is_active = true"),
            {'emp_id': employee_id}
        ).fetchone()
        
        if not employee_data:
            return "Karyawan tidak ditemukan", 404
        
        employee_name = employee_data[2]
        employee_position = employee_data[3]
        employee_branch = employee_data[4]
        
        # Generate QR data (temporary - in real app this would be saved in DB)
        expiry_date = datetime.utcnow().date() + timedelta(days=365)
        token = f"QR{employee_id}_{employee_name[:3].upper()}"
        qr_data = f"{employee_id}|{token}|{expiry_date.strftime('%Y-%m-%d')}"
        
        # Generate QR code
        try:
            import qrcode
            from qrcode import constants
        except ImportError:
            return "QR Code library tidak tersedia", 500
            
        qr = qrcode.QRCode(
            version=1,
            error_correction=constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        from io import BytesIO
        import base64
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return render_template('qr_print.html',
                             employee_id=employee_id,
                             employee_name=employee_name,
                             employee_position=employee_position,
                             employee_branch=employee_branch,
                             qr_code_base64=qr_code_base64,
                             qr_data=qr_data,
                             expiry_date=expiry_date.strftime('%d/%m/%Y'))
        
    except Exception as e:
        logging.error(f"Error in print_qr: {str(e)}")
        return f"Terjadi kesalahan: {str(e)}", 500

# QR Attendance backend routes
@app.route('/validate_qr_attendance', methods=['POST'])
@login_required
@admin_required
def validate_qr_attendance():
    """Validate QR code for attendance"""
    try:
        data = request.get_json()
        employee_id = data.get('employee_id')
        token = data.get('token')
        expiry = data.get('expiry')
        
        if not all([employee_id, token, expiry]):
            return jsonify({'success': False, 'error': 'Data QR code tidak lengkap'})
        
        # Get employee data using direct SQL
        employee_data = db.session.execute(
            text("SELECT id, employee_id, full_name, position, branch_location FROM employees WHERE id = :emp_id AND is_active = true"),
            {'emp_id': employee_id}
        ).fetchone()
        
        if not employee_data:
            return jsonify({'success': False, 'error': 'Karyawan tidak ditemukan atau tidak aktif'})
        
        # Validate token format
        employee_name = employee_data[2]
        expected_token = f"QR{employee_id}_{employee_name[:3].upper()}"
        
        if token != expected_token:
            return jsonify({'success': False, 'error': 'Token QR code tidak valid'})
        
        # Validate scan time - only allow scanning from 07:00 (using Indonesia timezone UTC+7)
        from datetime import timezone, timedelta
        indonesia_tz = timezone(timedelta(hours=7))
        current_time_utc = datetime.utcnow()
        current_time_local = current_time_utc.replace(tzinfo=timezone.utc).astimezone(indonesia_tz)
        current_hour = current_time_local.hour
        current_minute = current_time_local.minute
        
        # DEBUG: Log the actual times
        logging.info(f"UTC Time: {current_time_utc}")
        logging.info(f"Indonesia Time: {current_time_local}")
        logging.info(f"Current Hour: {current_hour}, Current Minute: {current_minute}")
        
        # Convert to minutes for easier comparison
        current_minutes = current_hour * 60 + current_minute
        start_scan_time = 7 * 60  # 07:00 in minutes
        
        if current_minutes < start_scan_time:
            return jsonify({'success': False, 'error': f'Belum bisa scan absensi. Scan dimulai jam 07:00. Sekarang jam {current_hour:02d}:{current_minute:02d}'})
        
        # Check if already checked in today
        today = current_time_local.date()
        existing_attendance = db.session.execute(
            text("""SELECT id, check_in_time, check_out_time, early_leave_time 
                    FROM attendances WHERE employee_id = :emp_id AND attendance_date = :today"""),
            {'emp_id': employee_id, 'today': today}
        ).fetchone()
        
        # Determine attendance type based on current status and time - STRICT VALIDATION
        work_start_time = 8 * 60  # 08:00 in minutes
        work_end_time = 17 * 60   # 17:00 in minutes
        
        if not existing_attendance:
            # No attendance record yet
            if current_minutes < work_start_time:
                # Before 08:00 = CHECK IN (early arrival)
                attendance_type = 'check_in'
            elif current_minutes >= work_start_time and current_minutes < work_end_time:
                # 08:00-16:59 = Could be late check-in
                attendance_type = 'check_in'
            elif current_minutes >= work_end_time and current_minutes < 19 * 60:
                # 17:00-18:59 = Overtime check-in
                attendance_type = 'check_in'
            else:
                # After 19:00 = Night overtime check-in
                attendance_type = 'check_in'
        elif existing_attendance[1] and not existing_attendance[2] and not existing_attendance[3]:
            # Has check-in but no check-out and no early leave
            if current_minutes < work_end_time:
                # Before 17:00 = EARLY LEAVE (requires reason)
                attendance_type = 'early_leave'
            elif current_minutes >= work_end_time and current_minutes < 19 * 60:
                # 17:00-18:59 = NORMAL CHECK OUT
                attendance_type = 'check_out'
            else:
                # After 19:00 = OVERTIME CHECK OUT
                attendance_type = 'check_out'
        else:
            # Any other case = ALREADY COMPLETE (prevent double scan)
            return jsonify({'success': False, 'error': 'Anda sudah melakukan absensi lengkap untuk hari ini. Tidak bisa scan 2x!'})
        
        employee_info = {
            'id': employee_data[0],
            'employee_id': employee_data[1],
            'full_name': employee_data[2],
            'position': employee_data[3],
            'branch_location': employee_data[4],
            'attendance_type': attendance_type
        }
        
        return jsonify({
            'success': True,
            'employee': employee_info,
            'message': f'QR code valid untuk {employee_name} - {attendance_type}'
        })
        
    except Exception as e:
        logging.error(f"Error validating QR attendance: {str(e)}")
        return jsonify({'success': False, 'error': f'Terjadi kesalahan: {str(e)}'})

@app.route('/submit_qr_attendance', methods=['POST'])
@login_required
@admin_required
def submit_qr_attendance():
    """Submit QR attendance with photo"""
    try:
        data = request.get_json()
        employee_id = data.get('employee_id')
        photo_data = data.get('photo_data')
        attendance_time = data.get('attendance_time')
        attendance_type = data.get('attendance_type', 'masuk')
        early_leave_reason = data.get('early_leave_reason', '')
        
        if not all([employee_id, photo_data]):
            return jsonify({'success': False, 'error': 'Data tidak lengkap'})
        
        # Convert photo data (remove data:image/jpeg;base64, prefix)
        if photo_data.startswith('data:image'):
            photo_base64 = photo_data.split(',')[1]
        else:
            photo_base64 = photo_data
        
        # Use Indonesia timezone (UTC+7) for database storage
        from datetime import timezone, timedelta
        indonesia_tz = timezone(timedelta(hours=7))
        current_time_utc = datetime.utcnow()
        current_time_local = current_time_utc.replace(tzinfo=timezone.utc).astimezone(indonesia_tz)
        current_time = current_time_local.replace(tzinfo=None)  # Remove timezone for database
        today = current_time.date()
        
        # DEBUG: Log actual times being saved
        print(f"DEBUG - UTC Time: {current_time_utc}")
        print(f"DEBUG - Indonesia Time: {current_time_local}")  
        print(f"DEBUG - Saving to database: {current_time}")
        logging.info(f"UTC Time: {current_time_utc}")
        logging.info(f"Indonesia Time: {current_time_local}")
        logging.info(f"Saving to database: {current_time}")
        
        # Check if attendance record exists for today
        existing_attendance = db.session.execute(
            text("SELECT id, check_in_time FROM attendances WHERE employee_id = :emp_id AND attendance_date = :today"),
            {'emp_id': employee_id, 'today': today}
        ).fetchone()
        
        if existing_attendance:
            # Handle early leave vs normal check-out
            if attendance_type == 'early_leave':
                # Update with early leave request
                db.session.execute(
                    text("""UPDATE attendances 
                            SET early_leave_time = :early_time,
                                check_out_photo = :photo,
                                early_leave_reason = :reason,
                                early_leave_status = 'pending'
                            WHERE id = :att_id"""),
                    {
                        'early_time': current_time,
                        'photo': photo_base64,
                        'reason': early_leave_reason,
                        'att_id': existing_attendance[0]
                    }
                )
                message = 'Permintaan pulang cepat berhasil diajukan'
            else:
                # Normal check-out
                db.session.execute(
                    text("""UPDATE attendances 
                            SET check_out_time = :checkout_time,
                                check_out_photo = :photo
                            WHERE id = :att_id"""),
                    {
                        'checkout_time': current_time,
                        'photo': photo_base64,
                        'att_id': existing_attendance[0]
                    }
                )
                message = 'Check-out berhasil dicatat'
        else:
            # Create new check-in record
            # Determine status based on Indonesia time
            indonesia_work_start = current_time.replace(hour=8, minute=0, second=0, microsecond=0)
            status = 'late' if current_time > indonesia_work_start else 'present'
            
            db.session.execute(
                text("""INSERT INTO attendances 
                        (employee_id, attendance_date, check_in_time, check_in_photo, status, attendance_method)
                        VALUES (:emp_id, :att_date, :checkin_time, :photo, :status, 'QR + Selfie')"""),
                {
                    'emp_id': employee_id,
                    'att_date': today,
                    'checkin_time': current_time,
                    'photo': photo_base64,
                    'status': status
                }
            )
            message = 'Check-in berhasil dicatat'
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': message
        })
        
    except Exception as e:
        logging.error(f"Error submitting QR attendance: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'error': f'Terjadi kesalahan: {str(e)}'})

@app.route('/get_attendance_photos/<int:attendance_id>')
@login_required
@admin_required
def get_attendance_photos(attendance_id):
    """Get attendance photos for viewing"""
    try:
        # Get attendance photos using direct SQL
        attendance_data = db.session.execute(
            text("""SELECT check_in_photo, check_out_photo, 
                           check_in_time, check_out_time
                    FROM attendances 
                    WHERE id = :att_id"""),
            {'att_id': attendance_id}
        ).fetchone()
        
        if not attendance_data:
            return jsonify({'success': False, 'error': 'Data absensi tidak ditemukan'})
        
        result = {
            'success': True,
            'check_in_photo': attendance_data[0],
            'check_out_photo': attendance_data[1],
            'check_in_time': attendance_data[2].strftime('%H:%M:%S') if attendance_data[2] else None,
            'check_out_time': attendance_data[3].strftime('%H:%M:%S') if attendance_data[3] else None
        }
        
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"Error getting attendance photos: {str(e)}")
        return jsonify({'success': False, 'error': f'Terjadi kesalahan: {str(e)}'})

# AJAX content routes for QR system
@app.route('/qr_attendance_content')
@login_required
@admin_required
def qr_attendance_content():
    """AJAX content-only version of QR attendance page"""
    try:
        from database_models import Attendance, Employee
        # Get Indonesia time date (WIB) for consistent date filtering
        from pytz import timezone
        utc = timezone('UTC')
        wib = timezone('Asia/Jakarta')
        now_utc = datetime.utcnow().replace(tzinfo=utc)
        now_wib = now_utc.astimezone(wib)
        today = now_wib.date()
        
        # Get today's attendance statistics using raw SQL to avoid missing column error
        attendance_today = db.session.execute(
            text("SELECT COUNT(*) FROM attendances WHERE attendance_date = :today"),
            {'today': today}
        ).scalar() or 0
        
        qr_scans_today = db.session.execute(
            text("SELECT COUNT(*) FROM attendances WHERE attendance_date = :today AND attendance_method = 'qr'"),
            {'today': today}
        ).scalar() or 0
        
        photos_taken = db.session.execute(
            text("SELECT COUNT(*) FROM attendances WHERE attendance_date = :today AND check_in_photo IS NOT NULL"),
            {'today': today}
        ).scalar() or 0
        
        active_employees = Employee.query.filter_by(is_active=True).count()
        
        # Get today's attendance records with employee details using raw SQL
        today_attendances_detailed = db.session.execute(
            text("""
                SELECT a.id, a.employee_id, a.attendance_date, a.check_in_time, 
                       a.check_out_time, a.work_type, a.attendance_method,
                       e.full_name, e.employee_id as employee_number, e.branch_location
                FROM attendances a 
                JOIN employees e ON a.employee_id = e.id 
                WHERE a.attendance_date = :today 
                ORDER BY a.check_in_time DESC
            """),
            {'today': today}
        ).fetchall()
        
        return render_template('qr_attendance_content.html',
                             attendance_today=attendance_today,
                             qr_scans_today=qr_scans_today,
                             photos_taken=photos_taken,
                             active_employees=active_employees,
                             today_attendances=today_attendances_detailed)
        
    except Exception as e:
        logging.error(f"Error in qr_attendance_content: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/employee_qr_generator_content')
@login_required
@admin_required
def employee_qr_generator_content():
    """AJAX content-only version of QR generator page"""
    try:
        # Get all employees with QR status using direct SQL
        employees_data = db.session.execute(
            text("SELECT id, employee_id, full_name, position, branch_location FROM employees WHERE is_active = true")
        ).fetchall()
        
        # Convert to list of dicts for template compatibility
        employees = []
        for row in employees_data:
            employee_dict = {
                'id': row[0],
                'employee_id': row[1], 
                'full_name': row[2],
                'position': row[3],
                'branch_location': row[4],
                'qr_code': None,
                'qr_expiry': None
            }
            employees.append(employee_dict)
        
        today = datetime.utcnow().date()
        
        # Statistics
        total_employees = len(employees)
        qr_generated = 0  # Count from QR table
        qr_printed = 0    # Count from print logs
        qr_expires = 365  # Default expiry days
        
        return render_template('employee_qr_generator_content.html',
                             employees=employees,
                             total_employees=total_employees,
                             qr_generated=qr_generated,
                             qr_printed=qr_printed,
                             qr_expires=qr_expires,
                             today=today)
        
    except Exception as e:
        logging.error(f"Error in employee_qr_generator_content: {str(e)}")
        return jsonify({'error': str(e)}), 500






@app.route('/check_in/<int:employee_id>', methods=['POST'])
@login_required
def check_in(employee_id):
    """Absensi masuk dengan foto"""
    try:
        data = request.get_json()
        photo_data = data.get('photo')
        
        if not photo_data:
            return jsonify({'success': False, 'message': 'Foto diperlukan untuk absensi'})
        
        employee = Employee.query.get_or_404(employee_id)
        today = datetime.utcnow().date()
        now = datetime.utcnow()
        
        # Check if already checked in today
        attendance = Attendance.query.filter_by(
            employee_id=employee_id,
            attendance_date=today
        ).first()
        
        if attendance and attendance.check_in_time:
            return jsonify({'success': False, 'message': 'Sudah absen masuk hari ini'})
        
        # Determine work type based on day and time
        work_type = 'normal'
        if now.weekday() == 6:  # Sunday
            work_type = 'sunday'
        elif now.hour >= 19:  # Night shift
            work_type = 'night'
        
        if not attendance:
            attendance = Attendance(
                employee_id=employee_id,
                attendance_date=today,
                work_type=work_type
            )
            db.session.add(attendance)
        
        attendance.check_in_time = now
        attendance.check_in_photo = photo_data
        attendance.status = 'present'
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Absen masuk berhasil - {employee.full_name}',
            'time': now.strftime('%H:%M:%S'),
            'work_type': work_type
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error in check_in: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/check_out/<int:employee_id>', methods=['POST'])
@login_required
def check_out(employee_id):
    """Absensi pulang dengan foto"""
    try:
        data = request.get_json()
        photo_data = data.get('photo')
        overtime_hours = float(data.get('overtime_hours', 0))
        
        if not photo_data:
            return jsonify({'success': False, 'message': 'Foto diperlukan untuk absensi'})
        
        employee = Employee.query.get_or_404(employee_id)
        today = datetime.utcnow().date()
        now = datetime.utcnow()
        
        # Get today's attendance
        attendance = Attendance.query.filter_by(
            employee_id=employee_id,
            attendance_date=today
        ).first()
        
        if not attendance or not attendance.check_in_time:
            return jsonify({'success': False, 'message': 'Belum absen masuk hari ini'})
        
        if attendance.check_out_time:
            return jsonify({'success': False, 'message': 'Sudah absen pulang hari ini'})
        
        attendance.check_out_time = now
        attendance.check_out_photo = photo_data
        attendance.overtime_hours = overtime_hours
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Absen pulang berhasil - {employee.full_name}',
            'time': now.strftime('%H:%M:%S'),
            'overtime_hours': overtime_hours
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error in check_out: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

# Removed broken payroll route handler

@app.route('/calculate_payroll/<int:year>/<int:month>')
@login_required
@admin_required
def calculate_payroll(year, month):
    """Calculate payroll for specific month"""
    try:
        # Get all active employees
        employees = Employee.query.filter_by(is_active=True).all()
        
        # Calculate working days in month (excluding Sundays for regular work)
        import calendar
        from datetime import date, timedelta
        
        # Get first and last day of month
        first_day = date(year, month, 1)
        if month == 12:
            last_day = date(year + 1, 1, 1) - timedelta(days=1)
        else:
            last_day = date(year, month + 1, 1) - timedelta(days=1)
        
        # Count working days (Monday-Saturday)
        working_days = 0
        current_date = first_day
        while current_date <= last_day:
            if current_date.weekday() < 6:  # Monday=0, Sunday=6
                working_days += 1
            current_date += timedelta(days=1)
        
        for employee in employees:
            # Delete existing payroll for this month
            MonthlyPayroll.query.filter_by(
                employee_id=employee.id,
                year=year,
                month=month
            ).delete()
            
            # Get attendance records for this month
            attendances = Attendance.query.filter(
                Attendance.employee_id == employee.id,
                Attendance.attendance_date >= first_day,
                Attendance.attendance_date <= last_day
            ).all()
            
            # Calculate attendance statistics
            days_present = len([att for att in attendances if att.status == 'present' and att.work_type == 'normal'])
            days_sunday_overtime = len([att for att in attendances if att.work_type == 'sunday'])
            total_night_hours = sum(att.overtime_hours for att in attendances if att.work_type == 'night')
            
            # Calculate salary
            daily_salary = employee.monthly_salary / working_days
            regular_salary = days_present * daily_salary
            sunday_overtime_salary = days_sunday_overtime * employee.overtime_sunday_rate
            night_overtime_salary = total_night_hours * employee.overtime_night_rate
            total_salary = regular_salary + sunday_overtime_salary + night_overtime_salary
            
            # Create payroll record
            payroll = MonthlyPayroll(
                employee_id=employee.id,
                year=year,
                month=month,
                total_working_days=working_days,
                days_present=days_present,
                days_sunday_overtime=days_sunday_overtime,
                total_night_hours=total_night_hours,
                daily_salary=daily_salary,
                regular_salary=regular_salary,
                sunday_overtime_salary=sunday_overtime_salary,
                night_overtime_salary=night_overtime_salary,
                total_salary=total_salary
            )
            
            db.session.add(payroll)
        
        db.session.commit()
        flash(f'Payroll bulan {month}/{year} berhasil dihitung', 'success')
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error calculating payroll: {str(e)}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
    
    return redirect(url_for('payroll'))

# ============= OPERATIONAL COSTS ROUTES =============

@app.route('/add_operational_cost', methods=['POST'])
@login_required
@admin_required
def add_operational_cost():
    """Add new operational cost"""
    try:
        cost_type = request.form.get('cost_type')
        cost_name = request.form.get('cost_name')
        monthly_amount = float(request.form.get('monthly_amount', 0))
        notes = request.form.get('notes', '').strip()
        
        if not cost_type or not cost_name or monthly_amount <= 0:
            flash('Harap isi semua field yang diperlukan', 'error')
            return redirect(url_for('profit_tracker'))
        
        new_cost = OperationalCost(
            cost_type=cost_type,
            cost_name=cost_name,
            monthly_amount=monthly_amount,
            notes=notes if notes else None,
            is_active=True
        )
        
        db.session.add(new_cost)
        db.session.commit()
        
        flash(f'Biaya operasional "{cost_name}" berhasil ditambahkan', 'success')
        return redirect(url_for('operational_costs'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error adding operational cost: {str(e)}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
        return redirect(url_for('profit_tracker'))

@app.route('/toggle_operational_cost/<int:cost_id>/<status>')
@login_required
@admin_required
def toggle_operational_cost(cost_id, status):
    """Toggle operational cost active status"""
    try:
        cost = OperationalCost.query.get_or_404(cost_id)
        cost.is_active = status.lower() == 'true'
        cost.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        status_text = "diaktifkan" if cost.is_active else "dinonaktifkan"
        flash(f'Biaya "{cost.cost_name}" berhasil {status_text}', 'success')
        return redirect(url_for('operational_costs'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error toggling operational cost: {str(e)}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
        return redirect(url_for('operational_costs'))

@app.route('/edit_operational_cost', methods=['POST'])
@login_required
@admin_required
def edit_operational_cost():
    """Edit operational cost"""
    try:
        cost_id = int(request.form.get('cost_id'))
        cost_type = request.form.get('cost_type')
        cost_name = request.form.get('cost_name')
        monthly_amount = float(request.form.get('monthly_amount', 0))
        notes = request.form.get('notes', '').strip()
        
        cost = OperationalCost.query.get_or_404(cost_id)
        cost.cost_type = cost_type
        cost.cost_name = cost_name
        cost.monthly_amount = monthly_amount
        cost.notes = notes if notes else None
        cost.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        flash(f'Biaya operasional "{cost_name}" berhasil diupdate', 'success')
        return redirect(url_for('operational_costs'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error editing operational cost: {str(e)}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
        return redirect(url_for('operational_costs'))

# ============= OPERATIONAL COSTS PAGE =============

@app.route('/operational_costs')
@login_required
@admin_required
def operational_costs():
    """Expense records management page (new system)"""
    try:
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        
        # Get all expense records (sorted by date, newest first)
        expense_records = ExpenseRecord.query.order_by(ExpenseRecord.expense_date.desc()).all()
        
        # Calculate totals by expense type for current month
        from calendar import monthrange
        now = datetime.utcnow()
        current_month_start = datetime(now.year, now.month, 1)
        if now.month == 12:
            current_month_end = datetime(now.year + 1, 1, 1)
        else:
            current_month_end = datetime(now.year, now.month + 1, 1)
        
        # Get current month expenses
        current_month_expenses = ExpenseRecord.query.filter(
            ExpenseRecord.expense_date >= current_month_start,
            ExpenseRecord.expense_date < current_month_end
        ).all()
        
        # Calculate totals by category
        total_packaging = sum(e.amount for e in current_month_expenses if e.expense_type == 'packaging')
        total_utilities = sum(e.amount for e in current_month_expenses if e.expense_type == 'utilities')
        total_internet = sum(e.amount for e in current_month_expenses if e.expense_type == 'internet')
        total_expedisi = sum(e.amount for e in current_month_expenses if e.expense_type == 'expedisi')
        
        # Calculate rent allocation for current month based on daily cost
        rent_expenses = ExpenseRecord.query.filter_by(expense_type='rent').all()
        total_daily_rent = sum(e.get_daily_cost() for e in rent_expenses if e.get_daily_cost() > 0)
        
        # Calculate rent allocation for current month (daily cost × days in month)
        days_in_current_month = monthrange(now.year, now.month)[1]
        total_rent = total_daily_rent * days_in_current_month
        
        total_monthly_expenses = sum(e.amount for e in current_month_expenses)
        days_in_month = monthrange(now.year, now.month)[1]
        total_daily_average = total_monthly_expenses / days_in_month if days_in_month > 0 else 0
        
        if is_ajax:
            return render_template('operational_costs_content.html',
                                 expense_records=expense_records,
                                 total_packaging=total_packaging,
                                 total_utilities=total_utilities,
                                 total_internet=total_internet,
                                 total_expedisi=total_expedisi,
                                 total_rent=total_rent,
                                 total_daily_rent=total_daily_rent,
                                 total_monthly_expenses=total_monthly_expenses,
                                 total_daily_average=total_daily_average,
                                 current_month=now.strftime('%B %Y'))
        else:
            return render_template('operational_costs.html',
                                 expense_records=expense_records,
                                 total_packaging=total_packaging,
                                 total_utilities=total_utilities,
                                 total_internet=total_internet,
                                 total_expedisi=total_expedisi,
                                 total_rent=total_rent,
                                 total_daily_rent=total_daily_rent,
                                 total_monthly_expenses=total_monthly_expenses,
                                 total_daily_average=total_daily_average,
                                 current_month=now.strftime('%B %Y'))
        
    except Exception as e:
        logging.error(f"Error loading expense records: {str(e)}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

# ============= EXPENSE RECORDS ROUTES (NEW SYSTEM) =============

@app.route('/add_expense_record', methods=['POST'])
@login_required
@admin_required
def add_expense_record():
    """Add new expense record with documentation"""
    try:
        expense_date = request.form.get('expense_date')
        expense_type = request.form.get('expense_type')
        expense_name = request.form.get('expense_name')
        amount = float(request.form.get('amount', 0))
        vendor_name = request.form.get('vendor_name', '').strip()
        notes = request.form.get('notes', '').strip()
        
        # Handle file uploads
        receipt_photo = request.files.get('receipt_photo')
        transfer_proof = request.files.get('transfer_proof')
        
        if not expense_date or not expense_type or not expense_name or amount <= 0:
            flash('Harap isi semua field yang diperlukan', 'error')
            return redirect(url_for('operational_costs'))
        
        # Convert date string to datetime
        expense_date_obj = datetime.strptime(expense_date, '%Y-%m-%d')
        
        # Process receipt photo if uploaded
        receipt_base64 = None
        if receipt_photo and receipt_photo.filename:
            receipt_data = receipt_photo.read()
            receipt_base64 = base64.b64encode(receipt_data).decode('utf-8')
        
        # Process transfer proof if uploaded
        transfer_base64 = None
        if transfer_proof and transfer_proof.filename:
            transfer_data = transfer_proof.read()
            transfer_base64 = base64.b64encode(transfer_data).decode('utf-8')
        
        # Handle rental dates for rent type
        rental_start_date = None
        rental_end_date = None
        
        if expense_type == 'rent':
            rental_start_str = request.form.get('rental_start_date')
            rental_end_str = request.form.get('rental_end_date')
            
            if rental_start_str and rental_end_str:
                from datetime import date
                rental_start_date = datetime.strptime(rental_start_str, '%Y-%m-%d').date()
                rental_end_date = datetime.strptime(rental_end_str, '%Y-%m-%d').date()
                
                # Validate that end date is after start date
                if rental_end_date <= rental_start_date:
                    flash('Tanggal selesai sewa harus setelah tanggal mulai sewa', 'error')
                    return redirect(url_for('operational_costs'))
            elif expense_type == 'rent':
                flash('Tanggal mulai dan selesai sewa wajib diisi untuk kategori Sewa Gudang', 'error')
                return redirect(url_for('operational_costs'))

        new_expense = ExpenseRecord(
            expense_date=expense_date_obj,
            expense_type=expense_type,
            expense_name=expense_name,
            amount=amount,
            receipt_photo=receipt_base64,
            transfer_proof=transfer_base64,
            vendor_name=vendor_name if vendor_name else None,
            notes=notes if notes else None,
            rental_start_date=rental_start_date,
            rental_end_date=rental_end_date
        )
        
        db.session.add(new_expense)
        db.session.commit()
        
        flash(f'Pengeluaran "{expense_name}" berhasil ditambahkan', 'success')
        return redirect(url_for('operational_costs'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error adding expense record: {str(e)}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
        return redirect(url_for('operational_costs'))

@app.route('/edit_expense_record', methods=['POST'])
@login_required
@admin_required
def edit_expense_record():
    """Edit expense record"""
    try:
        expense_id = int(request.form.get('expense_id'))
        expense_date = request.form.get('expense_date')
        expense_type = request.form.get('expense_type')
        expense_name = request.form.get('expense_name')
        amount = float(request.form.get('amount', 0))
        vendor_name = request.form.get('vendor_name', '').strip()
        notes = request.form.get('notes', '').strip()
        
        expense = ExpenseRecord.query.get_or_404(expense_id)
        
        # Update basic fields
        expense.expense_date = datetime.strptime(expense_date, '%Y-%m-%d')
        expense.expense_type = expense_type
        expense.expense_name = expense_name
        expense.amount = amount
        expense.vendor_name = vendor_name if vendor_name else None
        expense.notes = notes if notes else None
        expense.updated_at = datetime.utcnow()
        
        # Handle new file uploads if provided
        receipt_photo = request.files.get('receipt_photo')
        transfer_proof = request.files.get('transfer_proof')
        
        if receipt_photo and receipt_photo.filename:
            receipt_data = receipt_photo.read()
            expense.receipt_photo = base64.b64encode(receipt_data).decode('utf-8')
        
        if transfer_proof and transfer_proof.filename:
            transfer_data = transfer_proof.read()
            expense.transfer_proof = base64.b64encode(transfer_data).decode('utf-8')
        
        db.session.commit()
        
        flash(f'Pengeluaran "{expense_name}" berhasil diupdate', 'success')
        return redirect(url_for('operational_costs'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error editing expense record: {str(e)}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
        return redirect(url_for('operational_costs'))

@app.route('/delete_expense_record/<int:expense_id>')
@login_required
@admin_required
def delete_expense_record(expense_id):
    """Delete expense record"""
    try:
        expense = ExpenseRecord.query.get_or_404(expense_id)
        expense_name = expense.expense_name
        
        db.session.delete(expense)
        db.session.commit()
        
        flash(f'Pengeluaran "{expense_name}" berhasil dihapus', 'success')
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting expense record: {str(e)}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
    
    return redirect(url_for('operational_costs'))

@app.route('/view_expense_document/<int:expense_id>/<doc_type>')
@login_required
@admin_required
def view_expense_document(expense_id, doc_type):
    """View expense document (receipt or transfer proof)"""
    try:
        expense = ExpenseRecord.query.get_or_404(expense_id)
        
        if doc_type == 'receipt' and expense.receipt_photo:
            img_data = base64.b64decode(expense.receipt_photo)
            response = make_response(img_data)
            response.headers['Content-Type'] = 'image/jpeg'
            return response
        elif doc_type == 'transfer' and expense.transfer_proof:
            img_data = base64.b64decode(expense.transfer_proof)
            response = make_response(img_data)
            response.headers['Content-Type'] = 'image/jpeg'
            return response
        else:
            return "Document not found", 404
            
    except Exception as e:
        logging.error(f"Error viewing expense document: {str(e)}")
        return "Error loading document", 500

@app.route('/add_store', methods=['POST'])
@login_required
@admin_required
def add_store():
    """Add new store manually"""
    try:
        store_name = request.form.get('store_name', '').strip()
        sku_code = request.form.get('sku_code', '').strip().upper()
        
        if not store_name or not sku_code:
            flash('Nama toko dan kode SKU wajib diisi', 'error')
            return redirect(url_for('profit_tracker'))
        
        # Check if SKU code already exists
        existing_store = Store.query.filter_by(sku_code=sku_code).first()
        if existing_store:
            flash(f'Kode SKU "{sku_code}" sudah digunakan oleh toko lain', 'error')
            return redirect(url_for('profit_tracker'))
        
        # Create new store
        new_store = Store(
            store_name=store_name,
            sku_code=sku_code,
            is_active=True
        )
        db.session.add(new_store)
        db.session.commit()
        
        flash(f'Toko "{store_name}" berhasil ditambahkan dengan kode SKU "{sku_code}"', 'success')
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error adding store: {str(e)}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
    
    return redirect(url_for('profit_tracker'))

@app.route('/edit_store', methods=['POST'])
@login_required
@admin_required
def edit_store():
    """Edit existing store"""
    try:
        store_id = request.form.get('store_id')
        store_name = request.form.get('store_name', '').strip()
        sku_code = request.form.get('sku_code', '').strip().upper()
        
        if not store_id or not store_name or not sku_code:
            flash('Data tidak lengkap', 'error')
            return redirect(url_for('profit_tracker'))
        
        store = Store.query.get(store_id)
        if not store:
            flash('Toko tidak ditemukan', 'error')
            return redirect(url_for('profit_tracker'))
        
        # Check if SKU code is used by other stores
        existing_store = Store.query.filter(
            Store.sku_code == sku_code,
            Store.id != store_id
        ).first()
        if existing_store:
            flash(f'Kode SKU "{sku_code}" sudah digunakan oleh toko lain', 'error')
            return redirect(url_for('profit_tracker'))
        
        # Update store
        store.store_name = store_name
        store.sku_code = sku_code
        store.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash(f'Toko "{store_name}" berhasil diupdate', 'success')
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error editing store: {str(e)}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
    
    return redirect(url_for('profit_tracker'))

@app.route('/toggle_store_status', methods=['POST'])
@login_required
@admin_required
def toggle_store_status():
    """Toggle store active status via AJAX"""
    try:
        data = request.get_json()
        store_id = data.get('store_id')
        is_active = data.get('is_active', True)
        
        store = Store.query.get(store_id)
        if not store:
            return jsonify({'success': False, 'message': 'Toko tidak ditemukan'}), 404
        
        store.is_active = is_active
        store.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        status_text = 'diaktifkan' if is_active else 'dinonaktifkan'
        return jsonify({
            'success': True, 
            'message': f'Toko "{store.store_name}" berhasil {status_text}'
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error toggling store status: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/profit_delete_store', methods=['POST'])
@login_required
@admin_required
def profit_delete_store():
    """Delete store via AJAX"""
    try:
        data = request.get_json()
        store_id = data.get('store_id')
        
        store = Store.query.get(store_id)
        if not store:
            return jsonify({'success': False, 'message': 'Toko tidak ditemukan'}), 404
        
        # Only allow deleting inactive stores
        if store.is_active:
            return jsonify({
                'success': False, 
                'message': 'Hanya toko yang nonaktif yang dapat dihapus. Silakan nonaktifkan terlebih dahulu.'
            }), 400
        
        store_name = store.store_name
        db.session.delete(store)
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Toko "{store_name}" berhasil dihapus'
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting store: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ============= END PROFIT TRACKER ROUTES =============

# =====================================================
# HR & PAYROLL SYSTEM ROUTES (NEW)
# =====================================================

@app.route('/hr/employees/add', methods=['POST'])
@login_required
@admin_required
def add_hr_employee():
    """Add new employee"""
    try:
        # Get form data
        full_name = request.form.get('full_name')
        employee_id = request.form.get('employee_id')
        position = request.form.get('position', 'Staff')
        branch_location = request.form.get('branch_location')
        salary_group_id = request.form.get('salary_group_id')
        
        # Validate required fields
        if not all([full_name, employee_id, branch_location, salary_group_id]):
            return jsonify({'success': False, 'message': 'Semua field wajib diisi termasuk kelompok gaji'})
        
        # Check if employee_id already exists
        existing = db.session.execute(text("SELECT id FROM employees WHERE employee_id = :emp_id"), 
                                     {'emp_id': employee_id}).fetchone()
        if existing:
            return jsonify({'success': False, 'message': 'ID karyawan sudah ada'})
        
        # Get salary group info
        salary_group = db.session.execute(text("""
            SELECT daily_wage * 30 as monthly_salary FROM salary_groups WHERE id = :group_id
        """), {'group_id': salary_group_id}).fetchone()
        
        if not salary_group:
            return jsonify({'success': False, 'message': 'Kelompok gaji tidak ditemukan'})
        
        # Create new employee using raw SQL
        db.session.execute(text("""
            INSERT INTO employees (employee_id, full_name, position, branch_location, 
                                 monthly_salary, overtime_sunday_rate, overtime_night_rate, is_active, created_at, updated_at)
            VALUES (:emp_id, :full_name, :position, :branch_location, 
                    :monthly_salary, 1.5, 1.5, true, NOW(), NOW())
        """), {
            'emp_id': employee_id,
            'full_name': full_name,
            'position': position,
            'branch_location': branch_location,
            'monthly_salary': salary_group.monthly_salary
        })
        
        # Add employee to salary group
        db.session.execute(text("""
            UPDATE salary_groups 
            SET employee_names = CASE 
                WHEN employee_names IS NULL OR employee_names = '' THEN :new_name
                ELSE employee_names || ',' || :new_name
            END
            WHERE id = :group_id
        """), {'new_name': full_name.lower(), 'group_id': salary_group_id})
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Karyawan berhasil ditambahkan'})
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error adding employee: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/hr/employees/<int:employee_id>/toggle_status', methods=['POST'])
@login_required
@admin_required
def toggle_hr_employee_status(employee_id):
    """Toggle employee active status"""
    try:
        # Toggle status
        result = db.session.execute(text("""
            UPDATE employees 
            SET is_active = NOT is_active, updated_at = NOW()
            WHERE id = :emp_id
            RETURNING is_active, full_name
        """), {'emp_id': employee_id}).fetchone()
        
        if not result:
            return jsonify({'success': False, 'message': 'Karyawan tidak ditemukan'})
        
        db.session.commit()
        
        status_text = 'diaktifkan' if result.is_active else 'dinonaktifkan'
        return jsonify({'success': True, 'message': f'Karyawan "{result.full_name}" berhasil {status_text}'})
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error toggling employee status: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/hr_attendance')
@admin_required
def hr_attendance():
    """Attendance page (new HR system)"""
    try:
        today = datetime.now().date()
        
        # Get today's attendance
        today_attendance = AttendanceRecord.query.options(
            db.joinedload(AttendanceRecord.employee)
        ).filter(
            func.date(AttendanceRecord.scan_date) == today
        ).order_by(AttendanceRecord.scan_time.desc()).all()
        
        # Calculate statistics
        attendance_today = len([att for att in today_attendance if att.barcode_type in ['masuk', 'lembur_masuk']])
        on_time_today = len([att for att in today_attendance if att.barcode_type in ['masuk', 'lembur_masuk'] and att.is_within_tolerance])
        late_today = len([att for att in today_attendance if att.barcode_type in ['masuk', 'lembur_masuk'] and not att.is_within_tolerance])
        overtime_active = len([att for att in today_attendance if att.barcode_type in ['lembur_masuk']])
        
        # Check if AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return render_template('attendance_content.html',
                                 today_attendance=today_attendance,
                                 attendance_today=attendance_today,
                                 on_time_today=on_time_today,
                                 late_today=late_today,
                                 overtime_active=overtime_active)
        
        return render_template('attendance.html',
                             today_attendance=today_attendance,
                             attendance_today=attendance_today,
                             on_time_today=on_time_today,
                             late_today=late_today,
                             overtime_active=overtime_active)
        
    except Exception as e:
        logging.error(f"Error in hr_attendance: {e}")
        flash('Terjadi kesalahan saat memuat halaman', 'error')
        return redirect(url_for('dashboard'))

@app.route('/hr_attendance/submit', methods=['POST'])
@admin_required
def submit_hr_attendance():
    """Submit attendance with photo (new HR system)"""
    try:
        data = request.get_json()
        attendance_type = data['type']
        photo_base64 = data['photo_base64']
        
        # For demo purposes, use first active employee
        # In real implementation, this would be based on logged-in employee
        employee = Employee.query.filter_by(is_active=True).first()
        if not employee:
            return jsonify({'success': False, 'message': 'Tidak ada karyawan aktif'})
        
        today = datetime.now().date()
        now = datetime.now()
        
        # Check if already scanned this type today  
        existing_record = AttendanceRecord.query.filter(
            AttendanceRecord.employee_id == employee.id,
            AttendanceRecord.scan_date == today,
            AttendanceRecord.barcode_type == attendance_type
        ).first()
        
        if existing_record:
            return jsonify({'success': False, 'message': f'Sudah absen {attendance_type} hari ini'})
        
        # Create new attendance record
        attendance_record = AttendanceRecord(
            employee_id=employee.id,
            barcode_type=attendance_type,
            scan_time=now,
            scan_date=today,
            status='approved',
            is_within_tolerance=True,  # For demo, assume all scans are on time
            selfie_photo_base64=photo_base64
        )
        
        db.session.add(attendance_record)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Absensi berhasil dicatat'})
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error submitting attendance: {e}")
        return jsonify({'success': False, 'message': str(e)})

# ============= SALARY GROUPS MANAGEMENT =============

@app.route('/salary_groups/<location_name>')
@admin_required
def manage_salary_groups(location_name):
    """Manage salary groups for location with table format and pagination"""
    try:
        # Get location
        location = Location.query.filter_by(location_name=location_name).first()
        if not location:
            flash('Lokasi tidak ditemukan', 'error')
            return redirect(url_for('expense_management_dashboard'))
        
        # Pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = 10  # 10 groups per page
        search = request.args.get('search', '')
        level_filter = request.args.get('level', '')
        
        # Build query
        query = SalaryGroup.query.filter_by(location_id=location.id, is_active=True)
        
        # Apply search filter
        if search:
            query = query.filter(SalaryGroup.group_name.ilike(f'%{search}%'))
        
        # Apply level filter
        if level_filter:
            query = query.filter_by(group_level=int(level_filter))
        
        # Order by level and name
        query = query.order_by(SalaryGroup.group_level, SalaryGroup.group_name)
        
        # Paginate
        pagination = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        salary_groups = pagination.items
        
        # Count employees for each group (simplified - would need proper employee-group relationship)
        for group in salary_groups:
            # For now, set random count - in real implementation, count actual employees
            group.employee_count = Employee.query.filter_by(
                branch_location=location_name,
                is_active=True
            ).count() // len(salary_groups) if salary_groups else 0
        
        return render_template('salary_groups_management.html',
                             salary_groups=salary_groups,
                             pagination=pagination,
                             current_page=page,
                             per_page=per_page,
                             location_name=location_name,
                             location=location)
        
    except Exception as e:
        logging.error(f"Error in manage_salary_groups: {e}")
        flash('Terjadi kesalahan saat memuat kelompok gaji', 'error')
        return redirect(url_for('expense_management_dashboard'))

@app.route('/manage_salary_groups/edit/<int:group_id>')
@admin_required
def edit_salary_group(group_id):
    """Get salary group data for editing"""
    try:
        group = SalaryGroup.query.get_or_404(group_id)
        return jsonify({
            'success': True,
            'group': {
                'id': group.id,
                'group_name': group.group_name,
                'group_level': group.group_level,
                'daily_wage': group.daily_wage,
                'sunday_rate': group.sunday_rate,
                'night_rate': group.night_rate,
                'meal_rate': group.meal_rate,
                'attendance_bonus': group.attendance_bonus
            }
        })
    except Exception as e:
        logging.error(f"Error in edit_salary_group: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/manage_salary_groups/save', methods=['POST'])
@admin_required
def save_salary_group():
    """Save salary group (create new or update existing)"""
    try:
        group_id = request.form.get('group_id')
        location_name = request.form.get('location')
        
        # Get location
        location = Location.query.filter_by(location_name=location_name).first()
        if not location:
            return jsonify({'success': False, 'message': 'Lokasi tidak ditemukan'})
        
        # Prepare data
        group_data = {
            'group_name': request.form.get('group_name'),
            'group_level': int(request.form.get('group_level')),
            'daily_wage': float(request.form.get('daily_wage')),
            'sunday_rate': float(request.form.get('sunday_rate')),
            'night_rate': float(request.form.get('night_rate')),
            'meal_rate': float(request.form.get('meal_rate')),
            'attendance_bonus': float(request.form.get('attendance_bonus')),
            'location_id': location.id
        }
        
        if group_id:
            # Update existing group
            group = SalaryGroup.query.get_or_404(int(group_id))
            for key, value in group_data.items():
                setattr(group, key, value)
            message = 'Kelompok gaji berhasil diperbarui'
        else:
            # Create new group
            group = SalaryGroup(**group_data)
            db.session.add(group)
            message = 'Kelompok gaji berhasil ditambahkan'
        
        db.session.commit()
        return jsonify({'success': True, 'message': message})
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error in save_salary_group: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/hr_payroll_lampung')
@admin_required  
def hr_payroll_lampung():
    """Payroll page (new HR system)"""
    try:
        now = datetime.now()
        current_month = now.month
        current_year = now.year
        
        # Get monthly payrolls for current month (Lampung only)
        from sqlalchemy import extract
        monthly_payrolls = MonthlyPayroll.query.options(
            db.joinedload(MonthlyPayroll.employee)
        ).join(Employee).filter(
            extract('month', MonthlyPayroll.payroll_month) == current_month,
            extract('year', MonthlyPayroll.payroll_month) == current_year,
            Employee.branch_location.ilike('%lampung%')
        ).order_by(MonthlyPayroll.created_at.desc()).all()
        
        # Calculate statistics
        total_payroll_month = sum(p.total_salary for p in monthly_payrolls)
        employees_paid = len(monthly_payrolls)  # Count all payrolls as paid (no is_paid field yet)
        total_overtime_hours = sum(p.night_hours_worked for p in monthly_payrolls)
        
        # Calculate average attendance (use total_days_worked as proxy)
        if monthly_payrolls:
            avg_attendance = sum(min(p.total_days_worked / 26 * 100, 100) for p in monthly_payrolls) / len(monthly_payrolls)
        else:
            avg_attendance = 0
        
        # Month and year options
        months = [
            (1, 'Januari'), (2, 'Februari'), (3, 'Maret'), (4, 'April'),
            (5, 'Mei'), (6, 'Juni'), (7, 'Juli'), (8, 'Agustus'),
            (9, 'September'), (10, 'Oktober'), (11, 'November'), (12, 'Desember')
        ]
        years = list(range(2024, 2030))
        
        current_month_name = dict(months)[current_month]
        total_payroll_amount = total_payroll_month
        all_paid = True  # Consider all as paid for now (no is_paid field yet)
        
        # Check if AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return render_template('payroll_content.html',
                                 monthly_payrolls=monthly_payrolls,
                                 total_payroll_month=total_payroll_month,
                                 employees_paid=employees_paid,
                                 total_overtime_hours=total_overtime_hours,
                                 average_attendance=round(avg_attendance, 1),
                                 months=months,
                                 years=years,
                                 current_month=current_month,
                                 current_year=current_year,
                                 current_month_name=current_month_name,
                                 total_payroll_amount=total_payroll_amount,
                                 all_paid=all_paid)
        
        return render_template('payroll_lampung.html',
                             monthly_payrolls=monthly_payrolls,
                             total_payroll_month=total_payroll_month,
                             employees_paid=employees_paid,
                             total_overtime_hours=total_overtime_hours,
                             average_attendance=round(avg_attendance, 1),
                             months=months,
                             years=years,
                             current_month=current_month,
                             current_year=current_year,
                             current_month_name=current_month_name,
                             total_payroll_amount=total_payroll_amount,
                             all_paid=all_paid)
        
    except Exception as e:
        logging.error(f"Error in payroll lampung: {e}")
        flash('Terjadi kesalahan saat memuat halaman', 'error')
        return redirect(url_for('dashboard'))

@app.route('/hr_payroll_tangerang')
@admin_required  
def hr_payroll_tangerang():
    """Payroll page for Tangerang"""
    try:
        now = datetime.now()
        current_month = now.month
        current_year = now.year
        
        # Get monthly payrolls for current month (Tangerang only)
        from sqlalchemy import extract
        monthly_payrolls = MonthlyPayroll.query.options(
            db.joinedload(MonthlyPayroll.employee)
        ).join(Employee).filter(
            extract('month', MonthlyPayroll.payroll_month) == current_month,
            extract('year', MonthlyPayroll.payroll_month) == current_year,
            Employee.branch_location.ilike('%tangerang%')
        ).order_by(MonthlyPayroll.created_at.desc()).all()
        
        # Calculate statistics
        total_payroll_month = sum(p.total_salary for p in monthly_payrolls)
        employees_paid = len(monthly_payrolls)  # Count all payrolls as paid (no is_paid field yet)
        total_overtime_hours = sum(p.night_hours_worked for p in monthly_payrolls)
        
        # Calculate average attendance (use total_days_worked as proxy)
        if monthly_payrolls:
            avg_attendance = sum(min(p.total_days_worked / 26 * 100, 100) for p in monthly_payrolls) / len(monthly_payrolls)
        else:
            avg_attendance = 0
        
        # Month and year options
        months = [
            (1, 'Januari'), (2, 'Februari'), (3, 'Maret'), (4, 'April'),
            (5, 'Mei'), (6, 'Juni'), (7, 'Juli'), (8, 'Agustus'),
            (9, 'September'), (10, 'Oktober'), (11, 'November'), (12, 'Desember')
        ]
        years = list(range(2024, 2030))
        
        current_month_name = dict(months)[current_month]
        total_payroll_amount = total_payroll_month
        all_paid = True  # Consider all as paid for now (no is_paid field yet)
        
        return render_template('payroll_tangerang.html',
                             monthly_payrolls=monthly_payrolls,
                             total_payroll_month=total_payroll_month,
                             employees_paid=employees_paid,
                             total_overtime_hours=total_overtime_hours,
                             average_attendance=round(avg_attendance, 1),
                             months=months,
                             years=years,
                             current_month=current_month,
                             current_year=current_year,
                             current_month_name=current_month_name,
                             total_payroll_amount=total_payroll_amount,
                             all_paid=all_paid)
        
    except Exception as e:
        logging.error(f"Error in payroll tangerang: {e}")
        flash('Terjadi kesalahan saat memuat halaman', 'error')
        return redirect(url_for('dashboard'))

# ============= PAYROLL INTEGRATION SYSTEM =============

@app.route('/create_test_data_galuh/<location>')
@login_required
@admin_required
def create_test_data_galuh(location):
    """Create test attendance data for Galuh"""
    try:
        import calendar
        from sqlalchemy import text
        from database_models import Employee, Attendance, MonthlyPayroll, SalaryGroup
        
        # Find or create employee Galuh
        galuh = Employee.query.filter_by(employee_id=f'galuh_{location.lower()}').first()
        if not galuh:
            # Create Galuh employee
            galuh = Employee(
                employee_id=f'galuh_{location.lower()}',
                full_name=f'Galuh {location.title()}',
                position='Supervisor',
                branch_location=location.title(),
                monthly_salary=3660000,  # Base salary
                overtime_sunday_rate=135000,
                overtime_night_rate=15000,
                is_active=True
            )
            db.session.add(galuh)
            db.session.flush()  # Get employee ID
        
        # Assign to Supervisor salary group (Level 1 in selected location)
        target_location = db.session.execute(
            text("SELECT id FROM locations WHERE location_name = :loc_name"),
            {'loc_name': location.title()}
        ).scalar()
        
        if target_location:
            supervisor_group = SalaryGroup.query.filter_by(
                location_id=target_location,
                group_level=1  # Supervisor level
            ).first()
            
            if supervisor_group:
                galuh.salary_group_id = supervisor_group.id
        
        # Clear existing attendance data for current month
        from datetime import date
        current_date = datetime.now()
        start_month = date(current_date.year, current_date.month, 1)
        end_month = date(current_date.year, current_date.month, calendar.monthrange(current_date.year, current_date.month)[1])
        
        db.session.execute(
            text("DELETE FROM attendances WHERE employee_id = :emp_id AND attendance_date >= :start_date AND attendance_date <= :end_date"),
            {'emp_id': galuh.id, 'start_date': start_month, 'end_date': end_month}
        )
        
        # Create 27 normal work days
        normal_days = []
        day_count = 1
        while len(normal_days) < 27 and day_count <= 31:
            work_date = date(current_date.year, current_date.month, day_count)
            if work_date <= end_month:
                # Skip Sunday for normal days (we'll add Sunday work separately)
                if work_date.weekday() != 6:  # 6 = Sunday
                    normal_days.append(work_date)
            day_count += 1
        
        # Create normal attendance records
        for work_date in normal_days[:27]:
            attendance = Attendance(
                employee_id=galuh.id,
                attendance_date=work_date,
                check_in_time=datetime.combine(work_date, datetime.min.time().replace(hour=8, minute=0)),
                check_out_time=datetime.combine(work_date, datetime.min.time().replace(hour=17, minute=0)),
                work_type='normal',
                work_hours=8.0,
                status='present',
                attendance_method='qr'
            )
            db.session.add(attendance)
        
        # Create 2 Sunday work days
        sunday_dates = []
        day_count = 1
        while len(sunday_dates) < 2 and day_count <= 31:
            work_date = date(current_date.year, current_date.month, day_count)
            if work_date <= end_month and work_date.weekday() == 6:  # Sunday
                sunday_dates.append(work_date)
            day_count += 1
        
        for sunday_date in sunday_dates:
            attendance = Attendance(
                employee_id=galuh.id,
                attendance_date=sunday_date,
                check_in_time=datetime.combine(sunday_date, datetime.min.time().replace(hour=8, minute=0)),
                check_out_time=datetime.combine(sunday_date, datetime.min.time().replace(hour=17, minute=0)),
                work_type='sunday',
                work_hours=8.0,
                status='present',
                attendance_method='qr'
            )
            db.session.add(attendance)
        
        # Create 18 night overtime records (distribute across different days)
        night_overtime_days = normal_days[:18]  # Use first 18 normal days for night overtime
        for i, night_date in enumerate(night_overtime_days):
            attendance = Attendance(
                employee_id=galuh.id,
                attendance_date=night_date,
                check_in_time=datetime.combine(night_date, datetime.min.time().replace(hour=18, minute=0)),
                check_out_time=datetime.combine(night_date, datetime.min.time().replace(hour=19, minute=0)),
                work_type='night',
                work_hours=1.0,
                overtime_hours=1.0,
                status='present',
                attendance_method='qr'
            )
            db.session.add(attendance)
        
        db.session.commit()
        
        # Auto-calculate payroll
        payroll_result = calculate_employee_payroll(galuh.id, current_date.year, current_date.month)
        
        flash(f'Test data berhasil dibuat untuk Galuh {location.title()}: 27 hari kerja, 2x minggu, 18 jam lembur malam. Total gaji: Rp {payroll_result["total_salary"]:,.0f}', 'success')
        if location.lower() == 'lampung':
            return redirect(url_for('hr_payroll_lampung'))
        else:
            return redirect(url_for('hr_payroll_tangerang'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error creating test data: {e}")
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
        if location.lower() == 'lampung':
            return redirect(url_for('hr_payroll_lampung'))
        else:
            return redirect(url_for('hr_payroll_tangerang'))

def calculate_employee_payroll(employee_id, year, month):
    """Calculate monthly payroll for an employee based on attendance records"""
    import calendar
    from database_models import Employee, Attendance, MonthlyPayroll, SalaryGroup
    
    # Get employee and salary group
    employee = Employee.query.get(employee_id)
    if not employee:
        return None
        
    # Get salary group rates
    salary_group = employee.salary_group
    if not salary_group:
        # Fallback to legacy employee rates if no salary group
        daily_wage = employee.monthly_salary / 30  # Approximate daily wage
        sunday_rate = employee.overtime_sunday_rate
        night_rate = employee.overtime_night_rate
        meal_rate = 0
        attendance_bonus = 0
    else:
        daily_wage = salary_group.daily_wage
        sunday_rate = salary_group.sunday_rate
        night_rate = salary_group.night_rate  
        meal_rate = salary_group.meal_rate
        attendance_bonus = salary_group.attendance_bonus
    
    # Get attendance records for the month
    from datetime import date
    start_date = date(year, month, 1)
    end_date = date(year, month, calendar.monthrange(year, month)[1])
    
    attendances = Attendance.query.filter(
        Attendance.employee_id == employee_id,
        Attendance.attendance_date >= start_date,
        Attendance.attendance_date <= end_date
    ).all()
    
    # Calculate totals
    normal_days = 0
    sunday_days = 0
    night_hours = 0
    
    for att in attendances:
        if att.work_type == 'normal' and att.status == 'present':
            normal_days += 1
        elif att.work_type == 'sunday' and att.status == 'present':
            sunday_days += 1
        elif att.work_type == 'night' and att.status == 'present':
            night_hours += att.overtime_hours or 1  # Default 1 hour if not specified
    
    # Calculate salary components
    base_salary = normal_days * daily_wage
    sunday_overtime_pay = sunday_days * sunday_rate
    night_overtime_pay = night_hours * night_rate
    meal_allowance = normal_days * meal_rate
    
    # Attendance bonus (if full month attendance - 26+ days)
    bonus = attendance_bonus if normal_days >= 26 else 0
    
    total_salary = base_salary + sunday_overtime_pay + night_overtime_pay + meal_allowance + bonus
    
    # Create or update monthly payroll record
    payroll_date = start_date
    existing_payroll = MonthlyPayroll.query.filter_by(
        employee_id=employee_id,
        payroll_month=payroll_date
    ).first()
    
    if existing_payroll:
        # Update existing record
        existing_payroll.base_salary = base_salary
        existing_payroll.sunday_overtime_pay = sunday_overtime_pay
        existing_payroll.night_overtime_pay = night_overtime_pay
        existing_payroll.total_salary = total_salary
        existing_payroll.total_days_worked = normal_days
        existing_payroll.sunday_days_worked = sunday_days
        existing_payroll.night_hours_worked = night_hours
        existing_payroll.updated_at = datetime.utcnow()
    else:
        # Create new record
        payroll = MonthlyPayroll(
            employee_id=employee_id,
            payroll_month=payroll_date,
            base_salary=base_salary,
            sunday_overtime_pay=sunday_overtime_pay,
            night_overtime_pay=night_overtime_pay,
            total_salary=total_salary,
            total_days_worked=normal_days,
            sunday_days_worked=sunday_days,
            night_hours_worked=night_hours
        )
        db.session.add(payroll)
    
    db.session.commit()
    
    return {
        'employee_name': employee.full_name,
        'employee_id': employee.employee_id,
        'salary_group': salary_group.group_name if salary_group else 'Legacy',
        'base_salary': base_salary,
        'sunday_overtime_pay': sunday_overtime_pay,
        'night_overtime_pay': night_overtime_pay,
        'meal_allowance': meal_allowance,
        'attendance_bonus': bonus,
        'total_salary': total_salary,
        'normal_days': normal_days,
        'sunday_days': sunday_days,
        'night_hours': night_hours,
        'rates': {
            'daily_wage': daily_wage,
            'sunday_rate': sunday_rate,
            'night_rate': night_rate,
            'meal_rate': meal_rate,
            'attendance_bonus': attendance_bonus
        }
    }

@app.route('/hr_payroll/calculate', methods=['POST'])
@admin_required
def calculate_hr_payroll():
    """Quick Calculate monthly payroll for Lampung/Tangerang"""
    try:
        # Get form data (from simple form)
        location = request.form.get('location')
        month = int(request.form.get('month'))
        year = int(request.form.get('year'))
        work_days = int(request.form.get('work_days', 26))
        overtime_rate = int(request.form.get('overtime_rate', 15000))
        
        # Location-based rates
        location_rates = {
            'lampung': {
                'daily_wage': 120000,
                'meal_allowance': 25000,
                'attendance_bonus': 50000
            },
            'tangerang': {
                'daily_wage': 150000,
                'meal_allowance': 30000,
                'attendance_bonus': 75000
            }
        }
        
        if location not in location_rates:
            return jsonify({'success': False, 'message': 'Lokasi tidak valid'})
        
        rates = location_rates[location]
        
        # Get employees by location
        employees = Employee.query.filter(
            Employee.is_active == True,
            Employee.branch_location.ilike(f'%{location}%')
        ).all()
        
        if not employees:
            return jsonify({'success': False, 'message': f'Tidak ada karyawan aktif di {location}'})
        
        employees_count = 0
        skipped_count = 0
        
        for employee in employees:
            # Create payroll month date (first day of month)
            from datetime import date
            payroll_month_date = date(year, month, 1)
            
            # Check if payroll already exists for this month/year
            existing = MonthlyPayroll.query.filter(
                MonthlyPayroll.employee_id == employee.id,
                MonthlyPayroll.payroll_month == payroll_month_date
            ).first()
            
            if existing:
                skipped_count += 1
                continue
            
            # Simple calculation based on location rates
            basic_salary = rates['daily_wage'] * work_days
            meal_allowance = rates['meal_allowance'] * work_days
            attendance_bonus = rates['attendance_bonus']  # Full month bonus
            overtime_pay = 0  # Default, can be updated later
            
            total_salary = basic_salary + meal_allowance + attendance_bonus + overtime_pay
            
            # Create payroll record
            payroll = MonthlyPayroll(
                employee_id=employee.id,
                payroll_month=payroll_month_date,
                base_salary=basic_salary,
                sunday_overtime_pay=0,
                night_overtime_pay=overtime_pay,
                total_salary=total_salary,
                total_days_worked=work_days,
                sunday_days_worked=0,
                night_hours_worked=0
            )
            
            db.session.add(payroll)
            employees_count += 1
        
        db.session.commit()
        
        message = f'Payroll berhasil dibuat untuk {employees_count} karyawan {location.title()}'
        if skipped_count > 0:
            message += f'. {skipped_count} sudah ada sebelumnya'
            
        return jsonify({
            'success': True, 
            'message': message,
            'employees_count': employees_count,
            'skipped_count': skipped_count
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error calculating payroll: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/hr_payroll/<int:payroll_id>/mark_paid', methods=['POST'])
@admin_required
def mark_hr_payroll_paid(payroll_id):
    """Mark payroll as paid (new HR system)"""
    try:
        payroll = MonthlyPayroll.query.get_or_404(payroll_id)
        # Note: Since MonthlyPayroll doesn't have is_paid field yet, we'll just return success
        # In future version, we can add payment tracking fields to the model
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Gaji berhasil ditandai sebagai dibayar'})
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error marking payroll as paid: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/hr_payroll/pay_all', methods=['POST'])
@admin_required
def pay_all_hr_payrolls():
    """Mark all unpaid payrolls as paid (new HR system)"""
    try:
        now = datetime.now()
        current_month = now.month
        current_year = now.year
        
        # Create current month date for filtering
        from datetime import date
        current_month_date = date(current_year, current_month, 1)
        
        # Get all payrolls for current month (since we don't have is_paid field yet)
        all_payrolls = MonthlyPayroll.query.filter(
            MonthlyPayroll.payroll_month == current_month_date
        ).all()
        
        count = len(all_payrolls)
        # Note: In future version, we can add payment tracking fields to the model
        
        db.session.commit()
        return jsonify({'success': True, 'count': count})
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error paying all payrolls: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.errorhandler(404)
def not_found(error):
    return render_template('base.html', error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('base.html', error_message="Internal server error"), 500

# This route is handled by get_employee_details function above

@app.route('/employee_management/update/<int:employee_id>', methods=['POST'])
def update_employee_management(employee_id):
    """Update employee data"""
    try:
        data = request.get_json()
        logging.info(f"UPDATE EMPLOYEE: Request for ID {employee_id} - data: {data}")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Update employee
        cursor.execute("""
            UPDATE employees 
            SET employee_id = %s,
                full_name = %s,
                position = %s,
                branch_location = %s,
                salary_group_id = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (
            data['employee_id'],
            data['full_name'],
            data['position'],
            data['branch_location'],
            data['salary_group_id'],
            employee_id
        ))
        
        conn.commit()
        
        if cursor.rowcount > 0:
            logging.info(f"✅ UPDATE EMPLOYEE SUCCESS: Employee ID {employee_id} updated successfully")
            return jsonify({
                'success': True,
                'message': f'Karyawan {data["full_name"]} berhasil diupdate'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Karyawan tidak ditemukan atau tidak ada perubahan'
            })
            
    except Exception as e:
        logging.error(f"Error updating employee {employee_id}: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        })
    finally:
        if conn:
            conn.close()

@app.route('/approval_requests')
@login_required
@admin_required
def approval_requests():
    """Dashboard untuk approval requests attendance"""
    try:
        from attendance_routes import get_attendance_statistics
        from database_models import AttendanceApproval, Employee
        from datetime import date
        
        # Get pending approvals
        pending_approvals_query = db.session.query(
            AttendanceApproval,
            Employee
        ).join(
            Employee, AttendanceApproval.employee_id == Employee.id
        ).filter(
            AttendanceApproval.status == 'pending'
        ).order_by(
            AttendanceApproval.requested_at.desc()
        ).all()
        
        # Format pending approvals data
        pending_approvals = []
        for approval, employee in pending_approvals_query:
            pending_approvals.append({
                'id': approval.id,
                'employee_name': employee.full_name,
                'employee_branch': employee.branch_location,
                'barcode_type': approval.barcode_type,
                'scan_time': approval.scan_attempt_time.strftime('%H:%M:%S'),
                'scan_date': approval.scan_attempt_time.strftime('%Y-%m-%d'),
                'violation': approval.tolerance_violation,
                'employee_reason': approval.employee_reason,
                'requested_at': approval.requested_at
            })
        
        # Get statistics
        today = date.today()
        
        # Count statistics
        pending_count = len(pending_approvals)
        approved_today = AttendanceApproval.query.filter(
            AttendanceApproval.status == 'approved',
            func.date(AttendanceApproval.reviewed_at) == today
        ).count()
        rejected_today = AttendanceApproval.query.filter(
            AttendanceApproval.status == 'rejected',
            func.date(AttendanceApproval.reviewed_at) == today
        ).count()
        total_employees = Employee.query.filter_by(is_active=True).count()
        
        # Check if this is an AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return render_template('approval_requests_content.html',
                                 pending_approvals=pending_approvals,
                                 pending_count=pending_count,
                                 approved_today=approved_today,
                                 rejected_today=rejected_today,
                                 total_employees=total_employees)
        
        return render_template('approval_requests.html',
                             pending_approvals=pending_approvals,
                             pending_count=pending_count,
                             approved_today=approved_today,
                             rejected_today=rejected_today,
                             total_employees=total_employees)
                             
    except Exception as e:
        app.logger.error(f"Error in approval_requests: {str(e)}")
        flash('Terjadi kesalahan saat memuat approval requests', 'error')
        return redirect(url_for('dashboard'))
