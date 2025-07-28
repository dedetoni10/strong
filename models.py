import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging

# In-memory storage
orders: Dict[str, Dict] = {}
inventory: Dict[str, Dict] = {}
shopee_orders: Dict[str, Dict] = {}

def init_data():
    """Initialize empty data structures"""
    global orders, inventory, shopee_orders
    orders.clear()
    inventory.clear()
    shopee_orders.clear()
    logging.info("Data structures initialized")

class OrderStatus:
    PENDING = "pending"
    PROCESSING = "processing"
    SHIPPED = "shipped"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"

class Order:
    def __init__(self, order_id: str, shopee_order_id: str, customer_name: str, 
                 customer_phone: str, customer_address: str, items: List[Dict], 
                 total_amount: float, status: str = OrderStatus.PENDING):
        self.order_id = order_id
        self.shopee_order_id = shopee_order_id
        self.customer_name = customer_name
        self.customer_phone = customer_phone
        self.customer_address = customer_address
        self.items = items  # List of {"product_id": str, "quantity": int, "price": float}
        self.total_amount = total_amount
        self.status = status
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
    
    def to_dict(self):
        return {
            'order_id': self.order_id,
            'shopee_order_id': self.shopee_order_id,
            'customer_name': self.customer_name,
            'customer_phone': self.customer_phone,
            'customer_address': self.customer_address,
            'items': self.items,
            'total_amount': self.total_amount,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class InventoryItem:
    def __init__(self, product_id: str, name: str, sku: str, quantity: int, 
                 price: float, minimum_stock: int = 10):
        self.product_id = product_id
        self.name = name
        self.sku = sku
        self.quantity = quantity
        self.price = price
        self.minimum_stock = minimum_stock
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
    
    def to_dict(self):
        return {
            'product_id': self.product_id,
            'name': self.name,
            'sku': self.sku,
            'quantity': self.quantity,
            'price': self.price,
            'minimum_stock': self.minimum_stock,
            'is_low_stock': self.quantity <= self.minimum_stock,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

def create_order(shopee_order_id: str, customer_name: str, customer_phone: str, 
                customer_address: str, items: List[Dict], total_amount: float) -> str:
    """Create a new order"""
    order_id = str(uuid.uuid4())
    order = Order(order_id, shopee_order_id, customer_name, customer_phone, 
                  customer_address, items, total_amount)
    orders[order_id] = order.to_dict()
    logging.info(f"Created order {order_id}")
    return order_id

def get_order(order_id: str) -> Optional[Dict]:
    """Get order by ID"""
    return orders.get(order_id)

def update_order_status(order_id: str, status: str) -> bool:
    """Update order status"""
    if order_id in orders:
        orders[order_id]['status'] = status
        orders[order_id]['updated_at'] = datetime.now().isoformat()
        logging.info(f"Updated order {order_id} status to {status}")
        return True
    return False

def get_all_orders() -> List[Dict]:
    """Get all orders"""
    return list(orders.values())

def create_inventory_item(name: str, sku: str, quantity: int, price: float, 
                         minimum_stock: int = 10) -> str:
    """Create a new inventory item"""
    product_id = str(uuid.uuid4())
    item = InventoryItem(product_id, name, sku, quantity, price, minimum_stock)
    inventory[product_id] = item.to_dict()
    logging.info(f"Created inventory item {product_id}")
    return product_id

def get_inventory_item(product_id: str) -> Optional[Dict]:
    """Get inventory item by ID"""
    return inventory.get(product_id)

def update_inventory_quantity(product_id: str, quantity: int) -> bool:
    """Update inventory quantity"""
    if product_id in inventory:
        inventory[product_id]['quantity'] = quantity
        inventory[product_id]['updated_at'] = datetime.now().isoformat()
        logging.info(f"Updated inventory {product_id} quantity to {quantity}")
        return True
    return False

def get_all_inventory() -> List[Dict]:
    """Get all inventory items"""
    return list(inventory.values())

def delete_inventory_item(product_id: str) -> bool:
    """Delete inventory item"""
    if product_id in inventory:
        del inventory[product_id]
        logging.info(f"Deleted inventory item {product_id}")
        return True
    return False

def get_dashboard_stats() -> Dict:
    """Get dashboard statistics"""
    all_orders = get_all_orders()
    all_inventory = get_all_inventory()
    
    total_orders = len(all_orders)
    pending_orders = len([o for o in all_orders if o['status'] == OrderStatus.PENDING])
    processing_orders = len([o for o in all_orders if o['status'] == OrderStatus.PROCESSING])
    shipped_orders = len([o for o in all_orders if o['status'] == OrderStatus.SHIPPED])
    
    total_inventory_items = len(all_inventory)
    low_stock_items = len([i for i in all_inventory if i['is_low_stock']])
    
    total_revenue = sum(o['total_amount'] for o in all_orders 
                       if o['status'] in [OrderStatus.DELIVERED, OrderStatus.SHIPPED])
    
    return {
        'total_orders': total_orders,
        'pending_orders': pending_orders,
        'processing_orders': processing_orders,
        'shipped_orders': shipped_orders,
        'total_inventory_items': total_inventory_items,
        'low_stock_items': low_stock_items,
        'total_revenue': total_revenue
    }
