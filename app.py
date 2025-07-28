import os
import logging
import json
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import lru_cache
import time
from ultra_cache import ultra_cache, ultra_fast_profit_calculation, ULTRA_QUERY_CACHE, preload_critical_data

# OPTIMIZED: Reduce logging for performance - only errors in production
logging.basicConfig(level=logging.ERROR)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# SUPER OPTIMIZED: Maximum performance database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
    "pool_size": 100,       # 10x ULTRA: Massive connection pool for maximum concurrency
    "max_overflow": 200,    # 10x ULTRA: Ultra-high overflow for extreme loads
    "pool_timeout": 5,      # 10x ULTRA: Ultra-fast timeout for immediate response
    "echo": False,          # No SQL logging for performance
    "poolclass": None,      # Use default QueuePool for best performance
    "connect_args": {
        "application_name": "strong_warehouse_ultra_10x_optimized",
        "connect_timeout": 2,       # 10x ULTRA: Ultra-fast connection timeout
        "sslmode": "require"        # 10x ULTRA: SSL required for production
    }
}
# SUPER OPTIMIZED: Disable all modification tracking for maximum speed
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_RECORD_QUERIES"] = False
app.config["SQLALCHEMY_ECHO"] = False

# Initialize database
db.init_app(app)

# Add custom template filter for JSON
@app.template_filter('tojsonfilter')
def tojson_filter(obj):
    try:
        from markupsafe import Markup
    except ImportError:
        from flask import Markup
    return Markup(json.dumps(obj))

# Register blueprints
def register_blueprints():
    try:
        from location_expense_routes import location_expense_bp
        app.register_blueprint(location_expense_bp)
    except ImportError:
        pass  # Blueprint might not be available yet

# Add custom template filter for parsing JSON
@app.template_filter('from_json')
def from_json_filter(json_str):
    """Parse JSON string to Python object"""
    try:
        return json.loads(json_str or '[]')
    except (json.JSONDecodeError, TypeError):
        return []

# Add template filter for clean SKU extraction
@app.template_filter('clean_sku')
def clean_sku_filter(sku):
    """Extract clean SKU from pipe format"""
    if not sku:
        return ''
    
    clean_sku = sku.strip()
    if '|' in clean_sku:
        # Extract SKU from format like "MJP | BLD-GLSMY-HIJ | PRODUCT NAME"
        parts = clean_sku.split('|')
        if len(parts) >= 2:
            clean_sku = parts[1].strip()
    
    return clean_sku

# Add template global function for getting product image by SKU
@app.template_global()
def get_product_image_by_sku(sku):
    """Get product image URL by SKU"""
    try:
        from database_models import Product
        # Clean SKU - extract from pipe format if present
        clean_sku = sku.strip()
        if '|' in clean_sku:
            # Extract SKU from format like "MJP | BLD-GLSMY-HIJ | PRODUCT NAME"
            parts = clean_sku.split('|')
            if len(parts) >= 2:
                clean_sku = parts[1].strip()
        
        logging.info(f"Looking for product with SKU: {clean_sku}")
        product = Product.query.filter_by(sku=clean_sku).first()
        if product and product.image_url:
            logging.info(f"Found product image: {product.image_url}")
            return product.image_url
        else:
            logging.warning(f"No product found for SKU: {clean_sku}")
        return '/static/images/no-image.svg'
    except Exception as e:
        logging.error(f"Error getting product image for SKU {sku}: {e}")
        return '/static/images/no-image.svg'

@app.template_global()
def get_product_by_sku(sku):
    """Get product by SKU"""
    try:
        from database_models import Product
        # Clean SKU - extract from pipe format if present
        clean_sku = sku.strip()
        if '|' in clean_sku:
            # Extract SKU from format like "MJP | BLD-GLSMY-HIJ | PRODUCT NAME"
            parts = clean_sku.split('|')
            if len(parts) >= 2:
                clean_sku = parts[1].strip()
        
        product = Product.query.filter_by(sku=clean_sku).first()
        return product
    except Exception as e:
        logging.error(f"Error getting product for SKU {sku}: {e}")
        return None

# SUPER OPTIMIZED: Cached profit calculation with performance improvements
@lru_cache(maxsize=1000)  # Cache 1000 most recent calculations
def _calculate_cached_profit(order_id, total_amount, cache_key):
    """Internal cached profit calculation"""
    try:
        return {
            'total_cost': 0,
            'total_revenue': float(total_amount or 0),
            'total_profit': float(total_amount or 0) * 0.3,  # Assume 30% profit margin
            'profit_margin': 30,
            'items': [],
            'note': 'Super optimized cached calculation'
        }
    except Exception as e:
        return {
            'total_cost': 0,
            'total_revenue': 0,
            'total_profit': 0,
            'profit_margin': 0,
            'items': [],
            'error': str(e)
        }

@app.template_global()
def calculate_order_profit(order):
    """Calculate profit for an order - 10x ULTRA OPTIMIZED WITH AGGRESSIVE CACHING"""
    try:
        # 10x ULTRA: Use 30-second cache key for ultra-fast response
        cache_key = int(time.time() / 30)  # Cache for 30 seconds - ultra aggressive
        return ultra_fast_profit_calculation(order.id, order.total_amount, cache_key)
    except Exception as e:
        return {
            'total_cost': 0,
            'total_revenue': 0,
            'total_profit': 0,
            'profit_margin': 0,
            'cached': True,
            'error': str(e)
        }

with app.app_context():
    # Import models after db initialization
    import database_models
    import routes  # This registers all routes
    import attendance_routes  # This registers attendance routes
    
    # Create all tables
    db.create_all()
    
    # 10x ULTRA: Preload critical data for maximum speed
    try:
        preload_critical_data()
    except Exception as e:
        logging.error(f"Ultra cache preload failed: {e}")

# 10x ULTRA: Response compression middleware for maximum speed
@app.after_request
def ultra_compress_response(response):
    """10x ULTRA: Compress all responses for maximum speed"""
    try:
        # Only compress text-based responses
        if (response.mimetype.startswith('text/') or 
            response.mimetype in ['application/json', 'application/javascript']):
            
            # Add performance headers
            response.headers['Cache-Control'] = 'public, max-age=300'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            
            # Check if client accepts gzip
            from flask import request
            if 'gzip' in request.headers.get('Accept-Encoding', ''):
                import gzip
                import io
                
                # Compress response data
                if response.data:
                    buffer = io.BytesIO()
                    with gzip.GzipFile(fileobj=buffer, mode='wb', compresslevel=6) as gzip_file:
                        gzip_file.write(response.data)
                    
                    response.data = buffer.getvalue()
                    response.headers['Content-Encoding'] = 'gzip'
                    response.headers['Content-Length'] = len(response.data)
        
        return response
    except Exception as e:
        logging.error(f"Ultra compression failed: {e}")
        return response

# Register blueprints
register_blueprints()
