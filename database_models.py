from app import db
from datetime import datetime, date, time
from sqlalchemy import String, Integer, Float, DateTime, Date, Time, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from typing import Optional
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    __tablename__ = 'users'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False)  # 'admin', 'picker', 'packer', 'shipper'
    access: Mapped[str] = mapped_column(String(100), nullable=False)  # 'all', 'picking_only', 'packing_only', 'shipping_only', 'picking,packing', 'picking,shipping', etc.
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

class Order(db.Model):
    __tablename__ = 'orders'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    order_number: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    tracking_number: Mapped[Optional[str]] = mapped_column(String(100), unique=True)
    customer_name: Mapped[str] = mapped_column(String(200), nullable=False)
    customer_phone: Mapped[Optional[str]] = mapped_column(String(50))
    customer_address: Mapped[Optional[str]] = mapped_column(Text)
    total_amount: Mapped[float] = mapped_column(Float, default=0.0)
    order_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    
    # Status workflow: pending -> picking -> picked -> packing -> packed -> ready_for_pickup
    status: Mapped[str] = mapped_column(String(50), default='pending')
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Workflow timestamps
    picking_started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    picking_completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    packing_started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    packing_completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    ready_for_pickup_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    
    # Return/Retur functionality
    retur_photo_path: Mapped[Optional[str]] = mapped_column(String(500))  # Path to return photo
    return_photo_base64: Mapped[Optional[str]] = mapped_column(Text)  # Base64 encoded photo data
    return_photo_timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime)  # When photo was taken
    retur_processed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)  # When retur was processed
    jenis_retur: Mapped[Optional[str]] = mapped_column(String(50))  # Type: 'barang_rusak' or 'jual_kembali'
    retur_user: Mapped[Optional[str]] = mapped_column(String(100))  # Username who processed the return

class OrderItem(db.Model):
    __tablename__ = 'order_items'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    order_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('orders.id'), nullable=False)
    sku: Mapped[str] = mapped_column(String(100), nullable=False)
    product_name: Mapped[str] = mapped_column(String(500), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    price: Mapped[float] = mapped_column(Float, default=0.0)
    
    # Picking status for each item
    picked_quantity: Mapped[int] = mapped_column(Integer, default=0)
    is_picked: Mapped[bool] = mapped_column(Boolean, default=False)
    picked_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Product(db.Model):
    __tablename__ = 'products'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sku: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    barcode: Mapped[Optional[str]] = mapped_column(String(100))
    quantity: Mapped[int] = mapped_column(Integer, default=0)
    price: Mapped[float] = mapped_column(Float, default=0.0)
    minimum_stock: Mapped[int] = mapped_column(Integer, default=10)
    location: Mapped[Optional[str]] = mapped_column(String(100))  # Warehouse location
    image_url: Mapped[Optional[str]] = mapped_column(Text)  # Product image URL or data URL
    description: Mapped[Optional[str]] = mapped_column(Text)  # Product description/notes
    
    # Extended product information
    category: Mapped[Optional[str]] = mapped_column(String(100))  # Product category
    colour: Mapped[Optional[str]] = mapped_column(String(50))  # Product colour
    weight: Mapped[Optional[float]] = mapped_column(Float)  # Product weight in grams
    length: Mapped[Optional[float]] = mapped_column(Float)  # Product length in cm
    width: Mapped[Optional[float]] = mapped_column(Float)  # Product width in cm
    height: Mapped[Optional[float]] = mapped_column(Float)  # Product height in cm
    zone: Mapped[Optional[str]] = mapped_column(String(10))  # Storage zone
    rack: Mapped[Optional[str]] = mapped_column(String(10))  # Storage rack
    bin: Mapped[Optional[str]] = mapped_column(String(10))  # Storage bin
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Store(db.Model):
    __tablename__ = 'stores'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    store_name: Mapped[str] = mapped_column(String(200), nullable=False)  # e.g., "Mitra Jaya Parts"
    sku_code: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)  # e.g., "MJP"
    description: Mapped[Optional[str]] = mapped_column(Text)  # Optional store description
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ProfitSettings(db.Model):
    __tablename__ = 'profit_settings'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    admin_fee_percentage: Mapped[float] = mapped_column(Float, default=11.0)  # Admin fee percentage (11%)
    fee_per_order: Mapped[float] = mapped_column(Float, default=1250.0)  # Fee per order (1250 rupiah)
    insurance_fee: Mapped[float] = mapped_column(Float, default=350.0)  # Insurance fee per order (350 rupiah)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class DailyCost(db.Model):
    __tablename__ = 'daily_costs'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cost_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)  # Date for this cost
    advertising_cost: Mapped[float] = mapped_column(Float, default=0.0)  # Daily advertising cost
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Keep original OperationalCost for backward compatibility
class OperationalCost(db.Model):
    __tablename__ = 'operational_costs'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cost_type: Mapped[str] = mapped_column(String(50), nullable=False)  # 'staff_salary', 'packaging', 'rent', 'utilities'
    cost_name: Mapped[str] = mapped_column(String(200), nullable=False)  # Descriptive name
    monthly_amount: Mapped[float] = mapped_column(Float, nullable=False)  # Monthly cost amount
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)  # Active status
    notes: Mapped[Optional[str]] = mapped_column(Text)  # Additional notes
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# New ExpenseRecord model for actual expense tracking with documentation
class ExpenseRecord(db.Model):
    __tablename__ = 'expense_records'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    expense_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)  # Date of expense
    expense_type: Mapped[str] = mapped_column(String(50), nullable=False)  # 'packaging', 'utilities', 'internet', 'expedisi', 'rent'
    expense_name: Mapped[str] = mapped_column(String(200), nullable=False)  # Description of expense
    amount: Mapped[float] = mapped_column(Float, nullable=False)  # Actual amount spent
    receipt_photo: Mapped[Optional[str]] = mapped_column(Text)  # Base64 encoded receipt photo
    transfer_proof: Mapped[Optional[str]] = mapped_column(Text)  # Base64 encoded transfer proof
    vendor_name: Mapped[Optional[str]] = mapped_column(String(200))  # Vendor/supplier name
    notes: Mapped[Optional[str]] = mapped_column(Text)  # Additional notes
    
    # Rental-specific fields for calculating daily costs
    rental_start_date: Mapped[Optional[date]] = mapped_column(Date)  # Start date for rental contracts
    rental_end_date: Mapped[Optional[date]] = mapped_column(Date)  # End date for rental contracts
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def get_daily_cost(self):
        """Calculate daily cost for rental expenses"""
        if self.expense_type == 'rent' and self.rental_start_date and self.rental_end_date:
            duration_days = (self.rental_end_date - self.rental_start_date).days + 1
            if duration_days > 0:
                return self.amount / duration_days
        return 0.0

class PickingSession(db.Model):
    __tablename__ = 'picking_sessions'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    order_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('orders.id'), nullable=False)
    current_item_index: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    
class StockMovement(db.Model):
    __tablename__ = 'stock_movements'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    product_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('products.id'), nullable=False)
    order_id: Mapped[Optional[int]] = mapped_column(Integer, db.ForeignKey('orders.id'))
    movement_type: Mapped[str] = mapped_column(String(50), nullable=False)  # 'in', 'out', 'adjustment'
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(Text)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class ScanHistory(db.Model):
    __tablename__ = 'scan_history'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    barcode: Mapped[str] = mapped_column(String(100), nullable=False)
    order_id: Mapped[Optional[int]] = mapped_column(Integer, db.ForeignKey('orders.id'), nullable=True, default=None)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)  # 'picking', 'packing', 'ready_pickup'
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    message: Mapped[str] = mapped_column(String(500), nullable=False)
    order_number: Mapped[str] = mapped_column(String(100), nullable=False)
    customer_name: Mapped[str] = mapped_column(String(200), nullable=False)
    

    
    scanned_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class PickingAuditTrail(db.Model):
    __tablename__ = 'picking_audit_trail'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    order_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('orders.id'), nullable=False)
    order_number: Mapped[str] = mapped_column(String(100), nullable=False)
    customer_name: Mapped[str] = mapped_column(String(200), nullable=False)
    
    # User information
    user_id: Mapped[str] = mapped_column(String(100), nullable=False)
    user_name: Mapped[str] = mapped_column(String(200), nullable=False)
    user_role: Mapped[str] = mapped_column(String(50), nullable=False)
    
    # Picking details
    action: Mapped[str] = mapped_column(String(100), nullable=False)  # 'started_picking', 'completed_picking'
    items_count: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[Optional[str]] = mapped_column(Text)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class PackingAuditTrail(db.Model):
    __tablename__ = 'packing_audit_trail'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    order_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('orders.id'), nullable=False)
    order_number: Mapped[str] = mapped_column(String(100), nullable=False)
    customer_name: Mapped[str] = mapped_column(String(200), nullable=False)
    
    # User information
    user_id: Mapped[str] = mapped_column(String(100), nullable=False)
    user_name: Mapped[str] = mapped_column(String(200), nullable=False)
    user_role: Mapped[str] = mapped_column(String(50), nullable=False)
    
    # Packing details
    action: Mapped[str] = mapped_column(String(100), nullable=False)  # 'validation_started', 'validation_completed'
    validation_status: Mapped[str] = mapped_column(String(50), nullable=False)  # 'success', 'failed', 'pending'
    items_validated: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[Optional[str]] = mapped_column(Text)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    order_number: Mapped[str] = mapped_column(String(100), nullable=False)  # Nomor pesanan/resi
    tracking_number: Mapped[Optional[str]] = mapped_column(String(100))     # Tracking number (jika ada)
    user_name: Mapped[str] = mapped_column(String(200), nullable=False)     # Nama user yang scan
    activity_type: Mapped[str] = mapped_column(String(50), nullable=False)  # picking/packing/ready_pickup/retur
    status: Mapped[str] = mapped_column(String(20), default='success')      # success/failed
    notes: Mapped[Optional[str]] = mapped_column(Text)                      # Catatan tambahan
    
    # Timestamp aktivitas
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

# ============= ATTENDANCE & PAYROLL MODELS =============

class Employee(db.Model):
    __tablename__ = 'employees'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('users.id'), nullable=True)
    employee_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)  # ID karyawan
    full_name: Mapped[str] = mapped_column(String(100), nullable=False)
    position: Mapped[str] = mapped_column(String(50), nullable=False)  # Jabatan
    branch_location: Mapped[str] = mapped_column(String(50), nullable=False, default='Lampung')  # Lampung atau Tangerang
    
    # Salary Group Integration
    salary_group_id: Mapped[Optional[int]] = mapped_column(Integer, db.ForeignKey('salary_groups.id'), nullable=True)
    
    # Legacy fields (kept for backward compatibility)
    monthly_salary: Mapped[float] = mapped_column(Float, nullable=False, default=0)  # Gaji bulanan
    overtime_sunday_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0)  # Rate lembur minggu (harian)
    overtime_night_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0)  # Rate lembur malam (per jam)
    
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='employee_profile')
    attendances = db.relationship('Attendance', backref='employee', lazy='dynamic')
    salary_group = db.relationship('SalaryGroup', backref='employees')

class Attendance(db.Model):
    __tablename__ = 'attendances'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    employee_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('employees.id'), nullable=False)
    attendance_date: Mapped[date] = mapped_column(Date, nullable=False)
    
    # Absensi Masuk
    check_in_time: Mapped[Optional[datetime]] = mapped_column(DateTime)
    check_in_photo: Mapped[Optional[str]] = mapped_column(Text)  # Base64 photo
    
    # Absensi Pulang
    check_out_time: Mapped[Optional[datetime]] = mapped_column(DateTime)
    check_out_photo: Mapped[Optional[str]] = mapped_column(Text)  # Base64 photo
    
    # Work Type & Status
    work_type: Mapped[str] = mapped_column(String(20), default='normal')  # normal, sunday, night
    work_hours: Mapped[float] = mapped_column(Float, default=0)  # Total jam kerja
    overtime_hours: Mapped[float] = mapped_column(Float, default=0)  # Jam lembur malam
    status: Mapped[str] = mapped_column(String(20), default='present')  # present, absent, late
    
    # Attendance Method
    attendance_method: Mapped[str] = mapped_column(String(20), default='manual')  # manual, qr, fingerprint
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class MonthlyPayroll(db.Model):
    __tablename__ = 'monthly_payrolls'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    employee_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('employees.id'), nullable=False)
    payroll_month: Mapped[date] = mapped_column(Date, nullable=False)  # First day of month
    
    # Salary Components
    base_salary: Mapped[float] = mapped_column(Float, default=0)  # Gaji pokok
    sunday_overtime_pay: Mapped[float] = mapped_column(Float, default=0)  # Lembur minggu
    night_overtime_pay: Mapped[float] = mapped_column(Float, default=0)  # Lembur malam
    total_salary: Mapped[float] = mapped_column(Float, default=0)  # Total gaji
    
    # Work Statistics
    total_days_worked: Mapped[int] = mapped_column(Integer, default=0)
    sunday_days_worked: Mapped[int] = mapped_column(Integer, default=0)
    night_hours_worked: Mapped[float] = mapped_column(Float, default=0)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    employee = db.relationship('Employee', backref='monthly_payrolls')

# ============= LOCATION-BASED EXPENSE MODELS =============

class Location(db.Model):
    __tablename__ = 'locations'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    location_name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)  # 'Lampung', 'Tangerang'
    location_code: Mapped[str] = mapped_column(String(10), unique=True, nullable=False)  # 'LPG', 'TNG'
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ShopeeStore(db.Model):
    __tablename__ = 'shopee_stores'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    location_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('locations.id'), nullable=False)
    store_name: Mapped[str] = mapped_column(String(200), nullable=False)
    store_code: Mapped[str] = mapped_column(String(50), nullable=False)
    shopee_shop_id: Mapped[Optional[str]] = mapped_column(String(100))  # Shopee shop ID jika tersedia
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    location = db.relationship('Location', backref='shopee_stores')

class LocationExpense(db.Model):
    __tablename__ = 'location_expenses'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    location_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('locations.id'), nullable=False)
    expense_date: Mapped[date] = mapped_column(Date, nullable=False)
    expense_category: Mapped[str] = mapped_column(String(50), nullable=False)  # 'sewa', 'gaji', 'operasional', 'iklan'
    
    # Biaya Sewa
    warehouse_rent: Mapped[float] = mapped_column(Float, default=0.0)
    
    # Biaya Gaji (total harian untuk semua karyawan di lokasi)
    employee_salary: Mapped[float] = mapped_column(Float, default=0.0)
    
    # Biaya Operasional
    operational_cost: Mapped[float] = mapped_column(Float, default=0.0)
    operational_notes: Mapped[Optional[str]] = mapped_column(Text)
    
    # Total untuk hari ini
    total_amount: Mapped[float] = mapped_column(Float, default=0.0)
    
    notes: Mapped[Optional[str]] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(100), nullable=False)  # Username admin
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    location = db.relationship('Location', backref='expenses')

class StoreAdvertisingCost(db.Model):
    __tablename__ = 'store_advertising_costs'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    store_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('stores.id'), nullable=False)
    expense_date: Mapped[date] = mapped_column(Date, nullable=False)
    
    # Platform iklan
    platform: Mapped[str] = mapped_column(String(50), default='shopee')  # 'shopee', 'facebook', 'instagram', 'google'
    campaign_name: Mapped[Optional[str]] = mapped_column(String(200))
    
    # Biaya iklan
    daily_cost: Mapped[float] = mapped_column(Float, nullable=False)
    
    notes: Mapped[Optional[str]] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(100), nullable=False)  # Username admin
    
    # Edit tracking untuk non-admin users
    edit_count: Mapped[int] = mapped_column(Integer, default=0)  # Track berapa kali diedit
    edited_by: Mapped[Optional[str]] = mapped_column(String(100))  # Username yang terakhir edit
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    store = db.relationship('Store', backref='advertising_costs')

class LocationUser(db.Model):
    """Model untuk mengatur akses user berdasarkan lokasi"""
    __tablename__ = 'location_users'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('users.id'), nullable=False)
    location_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('locations.id'), nullable=False)
    
    # Access level
    can_view: Mapped[bool] = mapped_column(Boolean, default=True)
    can_input: Mapped[bool] = mapped_column(Boolean, default=True)
    can_manage: Mapped[bool] = mapped_column(Boolean, default=False)  # Untuk super admin
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='location_access')
    location = db.relationship('Location', backref='authorized_users')
    
    # Unique constraint: satu user hanya bisa punya satu role per lokasi
    __table_args__ = (db.UniqueConstraint('user_id', 'location_id'),)
    
    # Status
    status: Mapped[str] = mapped_column(String(20), default='present')  # present, absent, late
    notes: Mapped[Optional[str]] = mapped_column(Text)
    
    # Early Leave System
    early_leave_time: Mapped[Optional[datetime]] = mapped_column(DateTime)  # Jam pulang cepat
    early_leave_reason: Mapped[Optional[str]] = mapped_column(String(100))  # Alasan pulang cepat
    early_leave_approved_by: Mapped[Optional[str]] = mapped_column(String(100))  # Disetujui oleh
    early_leave_approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)  # Waktu approval
    early_leave_status: Mapped[str] = mapped_column(String(20), default='none')  # none, pending, approved, rejected
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SalaryGroup(db.Model):
    """Model untuk konfigurasi kelompok gaji per lokasi"""
    __tablename__ = 'salary_groups'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    location_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('locations.id'), nullable=False)
    
    # Group configuration
    group_name: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g., "Supervisor", "Admin", "Staff"
    group_level: Mapped[int] = mapped_column(Integer, nullable=False)  # 1-7 (1 = highest)
    
    # Salary rates
    daily_wage: Mapped[float] = mapped_column(Float, nullable=False)
    sunday_rate: Mapped[float] = mapped_column(Float, nullable=False)
    night_rate: Mapped[float] = mapped_column(Float, nullable=False)
    meal_rate: Mapped[float] = mapped_column(Float, default=0.0)
    attendance_bonus: Mapped[float] = mapped_column(Float, default=0.0)
    
    # Employee assignment (JSON format)
    employee_names: Mapped[Optional[str]] = mapped_column(Text)  # JSON array of employee names
    
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(100), nullable=False)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    location = db.relationship('Location', backref='salary_groups')
    
    # Unique constraint: one group level per location
    __table_args__ = (db.UniqueConstraint('location_id', 'group_level'),)

class EmployeeQRCode(db.Model):
    __tablename__ = 'employee_qr_codes'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    employee_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('employees.id'), nullable=False, unique=True)
    
    # QR Code data
    qr_data: Mapped[str] = mapped_column(Text, nullable=False)  # Encrypted data: employee_id|token|expiry_date
    qr_code_base64: Mapped[str] = mapped_column(Text, nullable=False)  # Base64 encoded PNG image
    security_token: Mapped[str] = mapped_column(String(100), nullable=False)  # Security validation token
    
    # Expiry and status
    generated_date: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expiry_date: Mapped[date] = mapped_column(Date, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    # Usage tracking
    scan_count: Mapped[int] = mapped_column(Integer, default=0)
    last_scan_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    print_count: Mapped[int] = mapped_column(Integer, default=0)
    last_print_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    
    # Relationships
    employee = db.relationship('Employee', backref='qr_code', uselist=False)
    
    def is_expired(self):
        """Check if QR code is expired"""
        return self.expiry_date < datetime.utcnow().date()
    
    def increment_scan(self):
        """Increment scan count and update last scan date"""
        self.scan_count += 1
        self.last_scan_date = datetime.utcnow()
    
    def increment_print(self):
        """Increment print count and update last print date"""
        self.print_count += 1
        self.last_print_date = datetime.utcnow()

# ============= ATTENDANCE SYSTEM MODELS =============

class AttendanceBarcode(db.Model):
    """Model untuk menyimpan 4 jenis barcode absensi per employee"""
    __tablename__ = 'attendance_barcodes'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    employee_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('employees.id'), nullable=False)
    barcode_type: Mapped[str] = mapped_column(String(50), nullable=False)  # 'masuk', 'keluar', 'lembur_masuk', 'lembur_keluar'
    barcode_data: Mapped[str] = mapped_column(String(500), nullable=False, unique=True)  # QR code data
    qr_data: Mapped[Optional[str]] = mapped_column(String(500))  # Alternative field name for QR data
    qr_code_base64: Mapped[Optional[str]] = mapped_column(Text)  # Base64 encoded QR code image
    target_time: Mapped[str] = mapped_column(String(10), nullable=False)  # '08:00', '17:00', '19:00', '22:00'
    window_start: Mapped[str] = mapped_column(String(10), nullable=False)  # Start time window
    window_end: Mapped[str] = mapped_column(String(10), nullable=False)  # End time window
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    employee = db.relationship('Employee', backref='attendance_barcodes')

class AttendanceRecord(db.Model):
    """Model untuk record absensi karyawan"""
    __tablename__ = 'attendance_records'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    employee_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('employees.id'), nullable=False)
    barcode_type: Mapped[str] = mapped_column(String(50), nullable=False)  # 'masuk', 'keluar', 'lembur_masuk', 'lembur_keluar'
    scan_time: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    scan_date: Mapped[date] = mapped_column(Date, nullable=False)
    
    # Status dan approval
    status: Mapped[str] = mapped_column(String(20), default='approved')  # 'approved', 'pending', 'rejected'
    is_within_tolerance: Mapped[bool] = mapped_column(Boolean, default=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(100))  # Username atasan
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    approval_notes: Mapped[Optional[str]] = mapped_column(Text)
    
    # Penalty system
    penalty_type: Mapped[Optional[str]] = mapped_column(String(20))  # 'none', 'half_day', 'full_day'
    salary_adjustment: Mapped[float] = mapped_column(Float, default=0.0)  # Amount deducted
    
    # Photo selfie
    selfie_photo_base64: Mapped[Optional[str]] = mapped_column(Text)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    employee = db.relationship('Employee', backref='attendance_records')

class AttendanceApproval(db.Model):
    """Model untuk request approval absensi di luar toleransi"""
    __tablename__ = 'attendance_approvals'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    employee_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('employees.id'), nullable=False)
    attendance_record_id: Mapped[Optional[int]] = mapped_column(Integer, db.ForeignKey('attendance_records.id'))
    
    # Request details
    requested_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    barcode_type: Mapped[str] = mapped_column(String(50), nullable=False)
    scan_attempt_time: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    tolerance_violation: Mapped[str] = mapped_column(String(100), nullable=False)  # 'late_arrival', 'early_departure', etc.
    employee_reason: Mapped[Optional[str]] = mapped_column(Text)
    
    # Approval status
    status: Mapped[str] = mapped_column(String(20), default='pending')  # 'pending', 'approved', 'rejected'
    reviewed_by: Mapped[Optional[str]] = mapped_column(String(100))  # Username atasan
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    reviewer_notes: Mapped[Optional[str]] = mapped_column(Text)
    
    # Penalty decision
    penalty_applied: Mapped[Optional[str]] = mapped_column(String(20))  # 'none', 'half_day', 'full_day'
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    employee = db.relationship('Employee', backref='attendance_approvals')
    attendance_record = db.relationship('AttendanceRecord', backref='approval_request')

class WorkSchedule(db.Model):
    __tablename__ = 'work_schedules'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    branch_location: Mapped[str] = mapped_column(String(50), nullable=False)  # Lampung, Tangerang
    schedule_type: Mapped[str] = mapped_column(String(20), nullable=False)    # masuk, keluar, lembur_malam, keluar_lembur
    target_time: Mapped[time] = mapped_column(Time, nullable=False)           # Target time (e.g., 08:00:00)
    tolerance_minutes: Mapped[int] = mapped_column(Integer, default=30)       # Tolerance window in minutes
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Unique constraint per branch and schedule type
    __table_args__ = (db.UniqueConstraint('branch_location', 'schedule_type', name='unique_branch_schedule'),)
    
    def __repr__(self):
        return f'<WorkSchedule {self.branch_location} - {self.schedule_type}: {self.target_time}>'
    
    @property
    def start_time(self):
        """Calculate tolerance start time"""
        from datetime import datetime, timedelta
        dummy_date = datetime.combine(datetime.today(), self.target_time)
        start_dt = dummy_date - timedelta(minutes=self.tolerance_minutes)
        return start_dt.time()
    
    @property 
    def end_time(self):
        """Calculate tolerance end time"""
        from datetime import datetime, timedelta
        dummy_date = datetime.combine(datetime.today(), self.target_time)
        end_dt = dummy_date + timedelta(minutes=self.tolerance_minutes)
        return end_dt.time()
    
    @property
    def window_display(self):
        """Display tolerance window as string"""
        return f"{self.start_time.strftime('%H:%M')} - {self.end_time.strftime('%H:%M')}"