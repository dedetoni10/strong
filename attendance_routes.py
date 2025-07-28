from flask import request, render_template, redirect, url_for, flash, jsonify, session
from app import db
from database_models import AttendanceBarcode, AttendanceRecord, AttendanceApproval, Employee, WorkSchedule
from datetime import datetime, date, time, timedelta
import qrcode
import io
import base64
import hashlib
import json
from typing import Dict, List, Tuple
from sqlalchemy import text

def init_attendance_routes(app):
    """Initialize attendance system routes"""
    
    @app.route('/attendance/employees', methods=['GET'])
    def get_attendance_employees():
        """Get employees data for QR generator interface"""
        try:
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 15))
            search = request.args.get('search', '').strip()
            branch = request.args.get('branch', '').strip()
            
            # Base query
            query = "SELECT id, employee_id, full_name, position, branch_location FROM employees WHERE is_active = true"
            count_query = "SELECT COUNT(*) FROM employees WHERE is_active = true"
            params = {}
            
            # Add search filter
            if search:
                query += " AND (full_name ILIKE :search OR employee_id ILIKE :search)"
                count_query += " AND (full_name ILIKE :search OR employee_id ILIKE :search)"
                params['search'] = f'%{search}%'
            
            # Add branch filter
            if branch:
                query += " AND branch_location = :branch"
                count_query += " AND branch_location = :branch"
                params['branch'] = branch
            
            # Add pagination
            offset = (page - 1) * per_page
            query += " ORDER BY full_name LIMIT :limit OFFSET :offset"
            params['limit'] = per_page
            params['offset'] = offset
            
            # Execute queries
            employees_data = db.session.execute(text(query), params).fetchall()
            total_count = db.session.execute(text(count_query), params).scalar()
            
            # Convert to list of dicts
            employees = []
            for row in employees_data:
                employees.append({
                    'id': row[0],
                    'employee_id': row[1],
                    'full_name': row[2],
                    'position': row[3],
                    'branch_location': row[4]
                })
            
            # Calculate pagination info
            total_pages = (total_count + per_page - 1) // per_page
            has_prev = page > 1
            has_next = page < total_pages
            
            return jsonify({
                'success': True,
                'employees': employees,
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': total_count,
                    'total_pages': total_pages,
                    'has_prev': has_prev,
                    'has_next': has_next
                }
            })
            
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    @app.route('/attendance/stats', methods=['GET'])
    def get_attendance_stats():
        """Get attendance statistics for QR generator"""
        try:
            total_employees = db.session.execute(
                text("SELECT COUNT(*) FROM employees WHERE is_active = true")
            ).scalar()
            
            qr_generated = db.session.execute(
                text("SELECT COUNT(DISTINCT employee_id) FROM attendance_barcodes")
            ).scalar()
            
            return jsonify({
                'success': True,
                'stats': {
                    'total_employees': total_employees or 0,
                    'qr_generated': qr_generated or 0,
                    'qr_printed': 0,  # Will be implemented later
                    'qr_expires': 365
                }
            })
            
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    @app.route('/attendance/generate_selected_barcodes', methods=['POST'])
    def generate_selected_barcodes():
        """Generate QR codes for selected employees"""
        try:
            data = request.get_json()
            employee_ids = data.get('employee_ids', [])
            
            if not employee_ids:
                return jsonify({'success': False, 'error': 'Tidak ada karyawan yang dipilih'})
            
            if len(employee_ids) > 15:
                return jsonify({'success': False, 'error': 'Maksimal 15 karyawan per batch'})
            
            # Get employee data
            placeholders = ','.join([':id' + str(i) for i in range(len(employee_ids))])
            params = {f'id{i}': emp_id for i, emp_id in enumerate(employee_ids)}
            
            employees_data = db.session.execute(
                text(f"SELECT id, employee_id, full_name FROM employees WHERE id IN ({placeholders}) AND is_active = true"),
                params
            ).fetchall()
            
            generated_qr_codes = []
            
            for emp_data in employees_data:
                emp_id = emp_data[0]
                employee_id = emp_data[1]
                full_name = emp_data[2]
                
                # Check if QR codes already exist (Pilihan A logic)
                existing_codes = db.session.execute(
                    text("SELECT barcode_type, qr_code_base64 FROM attendance_barcodes WHERE employee_id = :emp_id"),
                    {'emp_id': emp_id}
                ).fetchall()
                
                if existing_codes:
                    # Use existing QR codes
                    qr_codes = {}
                    for code_data in existing_codes:
                        qr_codes[code_data[0]] = code_data[1]
                else:
                    # Generate new QR codes
                    qr_codes = {}
                    today = datetime.now().strftime('%Y%m%d')
                    
                    barcode_types = ['MASUK', 'KELUAR', 'LEMBUR_MASUK', 'LEMBUR_KELUAR']
                    
                    # Time configuration for each barcode type
                    time_configs = {
                        'MASUK': {'target': '08:00', 'start': '07:30', 'end': '08:30'},
                        'KELUAR': {'target': '17:00', 'start': '17:00', 'end': '18:00'},
                        'LEMBUR_MASUK': {'target': '19:00', 'start': '18:30', 'end': '19:30'},
                        'LEMBUR_KELUAR': {'target': '22:00', 'start': '21:30', 'end': '22:30'}
                    }
                    
                    for barcode_type in barcode_types:
                        # Format: EMP_18|MASUK|20250725
                        qr_data = f"{employee_id}|{barcode_type}|{today}"
                        
                        # Generate QR code
                        qr = qrcode.QRCode(version=1, box_size=10, border=5)
                        qr.add_data(qr_data)
                        qr.make(fit=True)
                        
                        img = qr.make_image(fill_color="black", back_color="white")
                        buffer = io.BytesIO()
                        img.save(buffer, format='PNG')
                        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
                        
                        qr_codes[barcode_type] = qr_base64
                        
                        # Get time config for this barcode type
                        time_config = time_configs[barcode_type]
                        
                        # Save to database
                        barcode_record = AttendanceBarcode(
                            employee_id=emp_id,
                            barcode_type=barcode_type.lower(),
                            barcode_data=qr_data,
                            qr_data=qr_data,
                            qr_code_base64=qr_base64,
                            target_time=time_config['target'],
                            window_start=time_config['start'],
                            window_end=time_config['end']
                        )
                        db.session.add(barcode_record)
                
                generated_qr_codes.append({
                    'employee_id': employee_id,
                    'full_name': full_name,
                    'qr_codes': qr_codes
                })
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'qr_codes': generated_qr_codes
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)})
    
    @app.route('/attendance/generate_barcodes', methods=['POST'])
    def generate_attendance_barcodes():
        """Generate 4 jenis barcode absensi dengan time windows"""
        try:
            # Clear existing barcodes
            AttendanceBarcode.query.delete()
            
            # Define 4 barcode configurations
            barcode_configs = [
                {
                    'barcode_type': 'masuk',
                    'target_time': '08:00',
                    'window_start': '07:30',
                    'window_end': '08:30'
                },
                {
                    'barcode_type': 'keluar',
                    'target_time': '17:00',
                    'window_start': '17:00',
                    'window_end': '18:00'
                },
                {
                    'barcode_type': 'lembur_masuk',
                    'target_time': '19:00',
                    'window_start': '18:30',
                    'window_end': '19:30'
                },
                {
                    'barcode_type': 'lembur_keluar',
                    'target_time': '22:00',
                    'window_start': '20:00',
                    'window_end': '23:00'
                }
            ]
            
            generated_barcodes = []
            
            # Get all employees
            employees = Employee.query.filter_by(is_active=True).all()
            if not employees:
                return jsonify({
                    'success': False,
                    'message': 'Tidak ada karyawan aktif ditemukan'
                }), 400
            
            total_generated = 0
            
            for employee in employees:
                for config in barcode_configs:
                    # Create barcode data with employee info using employee_id
                    timestamp = datetime.now().strftime('%Y%m%d')
                    barcode_data = f"{employee.employee_id}|{config['barcode_type'].upper()}|{timestamp}"
                
                    # Create barcode record
                    barcode = AttendanceBarcode(
                        employee_id=employee.id,
                        barcode_type=config['barcode_type'],
                        barcode_data=barcode_data,
                        target_time=config['target_time'],
                        window_start=config['window_start'],
                        window_end=config['window_end']
                    )
                    
                    db.session.add(barcode)
                    total_generated += 1
                
            # Generate QR codes for display (semua karyawan)
            for employee in employees:
                for config in barcode_configs:
                    timestamp = datetime.now().strftime('%Y%m%d')
                    sample_barcode_data = f"{employee.employee_id}|{config['barcode_type'].upper()}|{timestamp}"
                    
                    # Generate QR code image
                    qr = qrcode.QRCode(version=1, box_size=10, border=5)
                    qr.add_data(sample_barcode_data)
                    qr.make(fit=True)
                    
                    qr_img = qr.make_image(fill_color="black", back_color="white")
                    buffer = io.BytesIO()
                    qr_img.save(buffer, format='PNG')
                    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
                    
                    generated_barcodes.append({
                        'type': config['barcode_type'],
                        'data': sample_barcode_data,
                        'target_time': config['target_time'],
                        'window': f"{config['window_start']} - {config['window_end']}",
                        'qr_image': f"data:image/png;base64,{qr_base64}",
                        'employee_name': employee.full_name,
                        'employee_id': employee.id
                    })
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Berhasil generate {total_generated} barcode untuk {len(employees)} karyawan',
                'barcodes': generated_barcodes,
                'total_employees': len(employees),
                'total_barcodes': total_generated
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'message': f'Error: {str(e)}'
            }), 500
    
    @app.route('/attendance/employees', methods=['GET'])
    def get_employees_for_qr():
        """Get all employees for QR generation interface"""
        try:
            employees = db.session.execute(
                text("""
                    SELECT e.id, e.full_name, e.branch_location, e.position, e.is_active,
                           CASE WHEN ab.employee_id IS NOT NULL THEN true ELSE false END as has_barcode
                    FROM employees e 
                    LEFT JOIN (
                        SELECT DISTINCT employee_id 
                        FROM attendance_barcodes
                    ) ab ON e.id = ab.employee_id
                    ORDER BY e.full_name
                """)
            ).fetchall()
            
            employee_list = []
            for emp in employees:
                employee_list.append({
                    'id': emp.id,
                    'full_name': emp.full_name,
                    'branch_location': emp.branch_location,
                    'position': emp.position,
                    'is_active': emp.is_active,
                    'has_barcode': emp.has_barcode
                })
            
            return jsonify({
                'success': True,
                'employees': employee_list
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error: {str(e)}'
            }), 500

    @app.route('/attendance/generate_selected_qr_new', methods=['POST'])
    def generate_selected_qr_new():
        try:
            data = request.get_json()
            employee_ids = data.get('employee_ids', [])
            
            if not employee_ids:
                return jsonify({
                    'success': False,
                    'message': 'Tidak ada karyawan yang dipilih'
                }), 400
            
            if len(employee_ids) > 15:
                return jsonify({
                    'success': False,
                    'message': 'Maksimal 15 karyawan per generate'
                }), 400
            
            # Get selected employees  
            employees = db.session.execute(
                text("SELECT id, employee_id, full_name, branch_location FROM employees WHERE id = ANY(:ids) AND is_active = true"),
                {'ids': employee_ids}
            ).fetchall()
            
            if not employees:
                return jsonify({
                    'success': False,
                    'message': 'Tidak ada karyawan aktif yang ditemukan'
                }), 400
            
            # Barcode configurations
            barcode_configs = [
                {'barcode_type': 'masuk', 'target_time': '08:00', 'window_start': '07:30', 'window_end': '08:30'},
                {'barcode_type': 'keluar', 'target_time': '17:00', 'window_start': '17:00', 'window_end': '18:00'},
                {'barcode_type': 'lembur_masuk', 'target_time': '19:00', 'window_start': '18:30', 'window_end': '19:30'},
                {'barcode_type': 'lembur_keluar', 'target_time': '22:00', 'window_start': '20:00', 'window_end': '23:00'}
            ]
            
            generated_qr_codes = []
            timestamp = datetime.now().strftime('%Y%m%d')
            
            for employee in employees:
                for config in barcode_configs:
                    # Check if barcode already exists (Pilihan A: Keep existing)
                    existing_barcode = db.session.execute(
                        text("""
                            SELECT barcode_data FROM attendance_barcodes 
                            WHERE employee_id = :emp_id AND barcode_type = :barcode_type
                        """),
                        {'emp_id': employee[0], 'barcode_type': config['barcode_type']}  # id is index 0
                    ).fetchone()
                    
                    if existing_barcode:
                        # Use existing barcode data
                        barcode_data = existing_barcode.barcode_data
                    else:
                        # Generate new barcode using employee_id (index 1 in query result)
                        barcode_data = f"{employee[1]}|{config['barcode_type'].upper()}|{timestamp}"
                        
                        # Save to database  
                        new_barcode = AttendanceBarcode(
                            employee_id=employee[0],  # id is index 0
                            barcode_type=config['barcode_type'],
                            barcode_data=barcode_data,
                            target_time=config['target_time'],
                            window_start=config['window_start'],
                            window_end=config['window_end']
                        )
                        db.session.add(new_barcode)
                    
                    # Generate QR code image
                    qr = qrcode.QRCode(version=1, box_size=10, border=5)
                    qr.add_data(barcode_data)
                    qr.make(fit=True)
                    
                    qr_img = qr.make_image(fill_color="black", back_color="white")
                    buffer = io.BytesIO()
                    qr_img.save(buffer, format='PNG')
                    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
                    
                    generated_qr_codes.append({
                        'employee_id': employee[0],  # id is index 0
                        'employee_name': employee[2],  # full_name is index 2
                        'type': config['barcode_type'],
                        'data': barcode_data,
                        'qr_image': f"data:image/png;base64,{qr_base64}"
                    })
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Berhasil generate {len(generated_qr_codes)} QR codes untuk {len(employees)} karyawan',
                'qr_codes': generated_qr_codes
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'message': f'Error: {str(e)}'
            }), 500

    @app.route('/attendance/decode_barcode', methods=['POST'])
    def decode_attendance_barcode():
        """Auto-detect employee and attendance type from barcode scan"""
        try:
            data = request.get_json()
            barcode_data = data.get('barcode_data')
            
            if not barcode_data:
                return jsonify({
                    'success': False,
                    'message': 'Barcode data diperlukan'
                }), 400
            
            # Parse barcode format: EMP_17|MASUK|20250724
            try:
                parts = barcode_data.split('|')
                if len(parts) != 3 or not parts[0].startswith('EMP_'):
                    return jsonify({
                        'success': False,
                        'message': 'Format barcode tidak valid'
                    }), 400
                
                # Use full employee_id from barcode (EMP_002, EMP_017, etc.)
                employee_id = parts[0]  # Keep full format: EMP_002
                barcode_type = parts[1].lower()
                scan_date = parts[2]
                
            except (ValueError, IndexError):
                return jsonify({
                    'success': False,
                    'message': 'Format barcode tidak dapat dibaca'
                }), 400
            
            # Find employee by exact employee_id match
            employee = Employee.query.filter_by(
                employee_id=employee_id,
                is_active=True
            ).first()
            if not employee or not employee.is_active:
                return jsonify({
                    'success': False,
                    'message': 'Karyawan tidak ditemukan atau tidak aktif'
                }), 404
            
            # Get work schedule from database untuk check tolerance
            work_schedule = WorkSchedule.query.filter_by(
                branch_location=employee.branch_location,
                schedule_type=barcode_type,
                is_active=True
            ).first()
            
            if not work_schedule:
                return jsonify({
                    'success': False,
                    'message': f'Jadwal kerja {barcode_type} untuk cabang {employee.branch_location} belum diatur. Hubungi admin.'
                }), 400
            
            # Check current time validation using WorkSchedule
            current_time = datetime.now().time()
            start_time = work_schedule.start_time
            end_time = work_schedule.end_time
            
            is_within_tolerance = start_time <= current_time <= end_time
            
            # Check if already scanned today
            today = date.today()
            existing_scan = AttendanceRecord.query.filter_by(
                employee_id=employee.id,  # Use actual employee.id
                barcode_type=barcode_type,
                scan_date=today
            ).first()
            
            if existing_scan:
                return jsonify({
                    'success': False,
                    'message': f'Sudah scan {barcode_type} hari ini pada {existing_scan.scan_time.strftime("%H:%M")}'
                }), 400
            
            return jsonify({
                'success': True,
                'employee': {
                    'id': employee.id,
                    'name': employee.full_name,
                    'employee_id': employee.employee_id,  # Use employee_id field instead of employee_number
                    'branch_location': employee.branch_location
                },
                'barcode_info': {
                    'type': barcode_type,
                    'target_time': work_schedule.target_time.strftime('%H:%M'),
                    'window': work_schedule.window_display,
                    'is_within_tolerance': is_within_tolerance,
                    'current_time': datetime.now().strftime('%H:%M')
                },
                'requires_approval': not is_within_tolerance
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error decode barcode: {str(e)}'
            }), 500
    
    @app.route('/attendance/scan', methods=['POST'])
    def scan_attendance():
        """Process attendance scan dengan approval workflow"""
        try:
            data = request.get_json()
            employee_id = data.get('employee_id')
            barcode_type = data.get('barcode_type')
            barcode_data = data.get('barcode_data')
            selfie_photo = data.get('selfie_photo')
            requires_approval = data.get('requires_approval', False)
            
            if not all([employee_id, barcode_type, barcode_data]):
                return jsonify({
                    'success': False,
                    'message': 'Data employee_id, barcode_type, dan barcode_data diperlukan'
                }), 400
            
            # Validate employee
            employee = Employee.query.get(employee_id)
            if not employee:
                return jsonify({
                    'success': False,
                    'message': 'Karyawan tidak ditemukan'
                }), 404
            
            # Validate barcode
            barcode = AttendanceBarcode.query.filter_by(
                employee_id=employee_id,
                barcode_type=barcode_type,
                barcode_data=barcode_data
            ).first()
            
            if not barcode:
                return jsonify({
                    'success': False,
                    'message': 'Barcode tidak valid'
                }), 404
            
            # Check current time
            current_time = datetime.now()
            current_time_str = current_time.strftime('%H:%M')
            current_date = current_time.date()
            
            # Parse time windows
            window_start = datetime.strptime(barcode.window_start, '%H:%M').time()
            window_end = datetime.strptime(barcode.window_end, '%H:%M').time()
            current_time_obj = current_time.time()
            
            # Check if within tolerance
            is_within_tolerance = window_start <= current_time_obj <= window_end
            
            if is_within_tolerance:
                # Auto-approve
                attendance_record = AttendanceRecord(
                    employee_id=employee_id,
                    barcode_type=barcode.barcode_type,
                    scan_time=current_time,
                    scan_date=current_date,
                    status='approved',
                    is_within_tolerance=True,
                    penalty_type='none',
                    selfie_photo_base64=selfie_photo
                )
                
                db.session.add(attendance_record)
                db.session.commit()
                
                return jsonify({
                    'success': True,
                    'status': 'approved',
                    'message': f'Absensi {barcode.barcode_type} berhasil! Waktu dalam toleransi.',
                    'scan_time': current_time.strftime('%H:%M:%S'),
                    'employee_name': employee.name
                })
            
            else:
                # Check for existing pending approval
                existing_approval = AttendanceApproval.query.filter_by(
                    employee_id=employee_id,
                    barcode_type=barcode.barcode_type,
                    status='pending'
                ).filter(
                    AttendanceApproval.requested_at >= datetime.combine(current_date, time.min)
                ).first()
                
                if existing_approval:
                    return jsonify({
                        'success': False,
                        'status': 'pending',
                        'message': 'Anda sudah memiliki request approval yang pending. Tunggu persetujuan atasan.'
                    })
                
                # Determine violation type
                if barcode.barcode_type == 'masuk' and current_time_obj > window_end:
                    violation = 'late_arrival'
                    violation_msg = f'Terlambat masuk ({current_time_str})'
                elif barcode.barcode_type == 'keluar' and current_time_obj < window_start:
                    violation = 'early_departure'
                    violation_msg = f'Pulang lebih awal ({current_time_str})'
                elif barcode.barcode_type == 'lembur_masuk' and current_time_obj > window_end:
                    violation = 'late_overtime'
                    violation_msg = f'Terlambat lembur ({current_time_str})'
                else:
                    violation = 'time_violation'
                    violation_msg = f'Di luar jam kerja ({current_time_str})'
                
                # Create approval request
                approval_request = AttendanceApproval(
                    employee_id=employee_id,
                    barcode_type=barcode.barcode_type,
                    scan_attempt_time=current_time,
                    tolerance_violation=violation,
                    employee_reason=data.get('reason', '')
                )
                
                db.session.add(approval_request)
                db.session.commit()
                
                return jsonify({
                    'success': False,
                    'status': 'pending_approval',
                    'message': f'Scan di luar toleransi waktu. {violation_msg}. Request approval telah dikirim ke atasan.',
                    'violation': violation_msg,
                    'target_window': f"{barcode.window_start} - {barcode.window_end}",
                    'scan_time': current_time_str
                })
                
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'message': f'Error: {str(e)}'
            }), 500
    
    @app.route('/attendance/approvals', methods=['GET'])
    def get_pending_approvals():
        """Get list pending approvals untuk dashboard atasan"""
        try:
            pending_approvals = db.session.query(
                AttendanceApproval,
                Employee
            ).join(
                Employee, AttendanceApproval.employee_id == Employee.id
            ).filter(
                AttendanceApproval.status == 'pending'
            ).order_by(
                AttendanceApproval.requested_at.desc()
            ).all()
            
            approvals_data = []
            for approval, employee in pending_approvals:
                approvals_data.append({
                    'id': approval.id,
                    'employee_name': employee.name,
                    'employee_branch': employee.branch_location,
                    'barcode_type': approval.barcode_type,
                    'scan_time': approval.scan_attempt_time.strftime('%H:%M:%S'),
                    'scan_date': approval.scan_attempt_time.strftime('%Y-%m-%d'),
                    'violation': approval.tolerance_violation,
                    'reason': approval.employee_reason or 'Tidak ada keterangan',
                    'requested_at': approval.requested_at.strftime('%Y-%m-%d %H:%M:%S')
                })
            
            return jsonify({
                'success': True,
                'approvals': approvals_data,
                'total_pending': len(approvals_data)
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error: {str(e)}'
            }), 500
    
    @app.route('/attendance/qr_stats', methods=['GET'])
    def get_qr_generator_stats():
        """Get attendance statistics untuk dashboard Generator QR"""
        try:
            # Count employees yang sudah punya barcode
            employees_with_barcode = db.session.query(
                AttendanceBarcode.employee_id
            ).distinct().count()
            
            # Count total employees
            total_employees = db.session.execute(
                text("SELECT COUNT(*) FROM employees WHERE is_active = true")
            ).scalar()
            
            return jsonify({
                'success': True,
                'stats': {
                    'total_employees': total_employees or 0,
                    'qr_generated': employees_with_barcode or 0,
                    'qr_printed': 0,
                    'qr_expires': 365
                }
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/attendance/approve/<int:approval_id>', methods=['POST'])
    def approve_attendance(approval_id):
        """Approve attendance request"""
        try:
            data = request.get_json()
            action = data.get('action')  # 'approve' or 'reject'
            penalty_type = data.get('penalty_type', 'none')  # 'none', 'half_day', 'full_day'
            reviewer_notes = data.get('notes', '')
            
            approval_request = AttendanceApproval.query.get(approval_id)
            if not approval_request:
                return jsonify({
                    'success': False,
                    'message': 'Request approval tidak ditemukan'
                }), 404
            
            if approval_request.status != 'pending':
                return jsonify({
                    'success': False,
                    'message': 'Request sudah diproses sebelumnya'
                }), 400
            
            current_user = session.get('username', 'admin')
            current_time = datetime.now()
            
            if action == 'approve':
                # Create attendance record
                attendance_record = AttendanceRecord(
                    employee_id=approval_request.employee_id,
                    barcode_type=approval_request.barcode_type,
                    scan_time=current_time,  # Use approval time as scan time
                    scan_date=current_time.date(),
                    status='approved',
                    is_within_tolerance=False,
                    approved_by=current_user,
                    approved_at=current_time,
                    approval_notes=reviewer_notes,
                    penalty_type=penalty_type,
                    salary_adjustment=calculate_penalty_amount(penalty_type, approval_request.employee_id)
                )
                
                db.session.add(attendance_record)
                
                # Update approval request
                approval_request.status = 'approved'
                approval_request.reviewed_by = current_user
                approval_request.reviewed_at = current_time
                approval_request.reviewer_notes = reviewer_notes
                approval_request.penalty_applied = penalty_type
                approval_request.attendance_record_id = attendance_record.id
                
                message = f'Absensi {approval_request.barcode_type} disetujui dengan penalty: {penalty_type}'
                
            else:  # reject
                approval_request.status = 'rejected'
                approval_request.reviewed_by = current_user
                approval_request.reviewed_at = current_time
                approval_request.reviewer_notes = reviewer_notes
                
                message = f'Absensi {approval_request.barcode_type} ditolak'
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': message,
                'action': action
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'message': f'Error: {str(e)}'
            }), 500

def calculate_penalty_amount(penalty_type: str, employee_id: int) -> float:
    """Calculate penalty amount based on penalty type and employee salary"""
    if penalty_type == 'none':
        return 0.0
    
    try:
        employee = Employee.query.get(employee_id)
        if not employee:
            return 0.0
        
        # Get daily wage (assuming you have this field or calculate from monthly salary)
        daily_wage = getattr(employee, 'daily_wage', 100000)  # Default 100k if not set
        
        if penalty_type == 'half_day':
            return daily_wage / 2
        elif penalty_type == 'full_day':
            return daily_wage
        
        return 0.0
        
    except Exception:
        return 0.0

def get_attendance_statistics() -> Dict:
    """Get attendance statistics for dashboard"""
    try:
        today = date.today()
        
        # Today's attendance
        attendance_today = AttendanceRecord.query.filter_by(scan_date=today).count()
        
        # Pending approvals
        pending_approvals = AttendanceApproval.query.filter_by(status='pending').count()
        
        # Within tolerance vs violations today
        approved_today = AttendanceRecord.query.filter_by(
            scan_date=today,
            is_within_tolerance=True
        ).count()
        
        violations_today = AttendanceRecord.query.filter_by(
            scan_date=today,
            is_within_tolerance=False
        ).count()
        
        return {
            'attendance_today': attendance_today,
            'pending_approvals': pending_approvals,
            'approved_today': approved_today,
            'violations_today': violations_today,
            'generated_barcodes': AttendanceBarcode.query.filter_by(is_active=True).count()
        }
        
    except Exception:
        return {
            'attendance_today': 0,
            'pending_approvals': 0,
            'approved_today': 0,
            'violations_today': 0,
            'generated_barcodes': 0
        }
    
    @app.route('/work_schedule_management')
    def work_schedule_management():
        """Admin page untuk pengaturan jam kerja"""
        # Get existing schedules
        schedules = WorkSchedule.query.order_by(WorkSchedule.branch_location, WorkSchedule.schedule_type).all()
        
        # Group by branch
        schedules_by_branch = {}
        for schedule in schedules:
            if schedule.branch_location not in schedules_by_branch:
                schedules_by_branch[schedule.branch_location] = {}
            schedules_by_branch[schedule.branch_location][schedule.schedule_type] = schedule
        
        return render_template('work_schedule_management.html', schedules_by_branch=schedules_by_branch)
    
    @app.route('/work_schedule_management_content')
    def work_schedule_management_content():
        """Content-only version for AJAX"""
        schedules = WorkSchedule.query.order_by(WorkSchedule.branch_location, WorkSchedule.schedule_type).all()
        
        schedules_by_branch = {}
        for schedule in schedules:
            if schedule.branch_location not in schedules_by_branch:
                schedules_by_branch[schedule.branch_location] = {}
            schedules_by_branch[schedule.branch_location][schedule.schedule_type] = schedule
        
        return render_template('work_schedule_management_content.html', schedules_by_branch=schedules_by_branch)
    
    @app.route('/work_schedule/save', methods=['POST'])
    def save_work_schedule():
        """Save or update work schedule"""
        try:
            branch_location = request.form.get('branch_location')
            schedule_type = request.form.get('schedule_type')
            target_time_str = request.form.get('target_time')
            tolerance_minutes = int(request.form.get('tolerance_minutes', 30))
            
            # Convert time string to time object
            target_time = datetime.strptime(target_time_str, '%H:%M').time()
            
            # Check if schedule exists
            existing_schedule = WorkSchedule.query.filter_by(
                branch_location=branch_location,
                schedule_type=schedule_type
            ).first()
            
            if existing_schedule:
                # Update existing
                existing_schedule.target_time = target_time
                existing_schedule.tolerance_minutes = tolerance_minutes
                existing_schedule.updated_at = datetime.utcnow()
            else:
                # Create new
                new_schedule = WorkSchedule(
                    branch_location=branch_location,
                    schedule_type=schedule_type,
                    target_time=target_time,
                    tolerance_minutes=tolerance_minutes
                )
                db.session.add(new_schedule)
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Jadwal {schedule_type} untuk {branch_location} berhasil disimpan'
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'message': f'Error: {str(e)}'
            }), 500
    
    @app.route('/work_schedule/get_tolerance/<branch>/<schedule_type>')
    def get_work_schedule_tolerance(branch, schedule_type):
        """Get tolerance info for specific branch and schedule type"""
        try:
            schedule = WorkSchedule.query.filter_by(
                branch_location=branch,
                schedule_type=schedule_type,
                is_active=True
            ).first()
            
            if not schedule:
                return jsonify({
                    'success': False,
                    'message': 'Schedule not found'
                }), 404
            
            return jsonify({
                'success': True,
                'target_time': schedule.target_time.strftime('%H:%M'),
                'tolerance_minutes': schedule.tolerance_minutes,
                'start_time': schedule.start_time.strftime('%H:%M'),
                'end_time': schedule.end_time.strftime('%H:%M'),
                'window_display': schedule.window_display
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error: {str(e)}'
            }), 500