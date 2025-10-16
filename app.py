# app.py - Complete Local Food Marketplace Backend
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import logging
from math import radians, sin, cos, sqrt, atan2
import os
import random
import string

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'farmconnect-secret-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///farmconnect.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-2024')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    farmer_profile = db.relationship('Farmer', backref='user', uselist=False, lazy=True)
    buyer_profile = db.relationship('Buyer', backref='user', uselist=False, lazy=True)
    
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Farmer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    farm_name = db.Column(db.String(200), nullable=False, index=True)
    description = db.Column(db.Text)
    address = db.Column(db.String(300), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    contact_phone = db.Column(db.String(20))
    contact_email = db.Column(db.String(120))
    delivery_radius_km = db.Column(db.Float, default=10.0)
    is_verified = db.Column(db.Boolean, default=False)
    profile_image = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    products = db.relationship('Product', backref='farmer', lazy=True)
    reviews = db.relationship('Review', backref='farmer', lazy=True)
    orders = db.relationship('Order', backref='farmer', lazy=True)

class Buyer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(300))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    contact_phone = db.Column(db.String(20))
    profile_image = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    reviews = db.relationship('Review', backref='buyer', lazy=True)
    orders = db.relationship('Order', backref='buyer', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    farmer_id = db.Column(db.Integer, db.ForeignKey('farmer.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False, index=True)
    description = db.Column(db.Text)
    category = db.Column(db.String(100), nullable=False)
    price_per_unit = db.Column(db.Float, nullable=False)
    unit_type = db.Column(db.String(50), nullable=False)
    current_stock = db.Column(db.Float, nullable=False)
    min_stock_alert = db.Column(db.Float, default=0)
    is_available = db.Column(db.Boolean, default=True)
    image_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    order_items = db.relationship('OrderItem', backref='product', lazy=True)
    availability_calendar = db.relationship('AvailabilityCalendar', backref='product', lazy=True)

class AvailabilityCalendar(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    farmer_id = db.Column(db.Integer, db.ForeignKey('farmer.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    available_quantity = db.Column(db.Float, nullable=False)
    is_available = db.Column(db.Boolean, default=True)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_number = db.Column(db.String(50), unique=True, nullable=False, index=True)
    farmer_id = db.Column(db.Integer, db.ForeignKey('farmer.id'), nullable=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey('buyer.id'), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default='pending')
    delivery_address = db.Column(db.String(300))
    delivery_instructions = db.Column(db.Text)
    order_date = db.Column(db.DateTime, default=datetime.utcnow)
    delivery_date = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    order_items = db.relationship('OrderItem', backref='order', lazy=True)
    messages = db.relationship('Message', backref='order', lazy=True)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    unit_price = db.Column(db.Float, nullable=False)
    total_price = db.Column(db.Float, nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    sender_id = db.Column(db.Integer, nullable=False)
    sender_type = db.Column(db.String(20), nullable=False)
    message_text = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    farmer_id = db.Column(db.Integer, db.ForeignKey('farmer.id'), nullable=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey('buyer.id'), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Utility Functions
def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371.0
    lat1_rad = radians(lat1)
    lon1_rad = radians(lon1)
    lat2_rad = radians(lat2)
    lon2_rad = radians(lon2)
    
    dlon = lon2_rad - lon1_rad
    dlat = lat2_rad - lat1_rad
    
    a = sin(dlat / 2)**2 + cos(lat1_rad) * cos(lat2_rad) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    
    return R * c

def generate_order_number():
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"ORD{timestamp}{random_str}"

# Authentication Routes
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        required_fields = ['email', 'password', 'user_type']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'User already exists'}), 400
        
        new_user = User(
            email=data['email'],
            user_type=data['user_type']
        )
        new_user.set_password(data['password'])
        
        db.session.add(new_user)
        db.session.commit()
        
        if data['user_type'] == 'farmer':
            farmer_profile = Farmer(
                user_id=new_user.id,
                farm_name=data.get('farm_name', ''),
                address=data.get('address', ''),
                latitude=data.get('latitude', 0),
                longitude=data.get('longitude', 0),
                contact_phone=data.get('contact_phone', ''),
                contact_email=data.get('contact_email', data['email'])
            )
            db.session.add(farmer_profile)
        
        elif data['user_type'] == 'buyer':
            buyer_profile = Buyer(
                user_id=new_user.id,
                full_name=data.get('full_name', ''),
                address=data.get('address', ''),
                latitude=data.get('latitude', 0),
                longitude=data.get('longitude', 0),
                contact_phone=data.get('contact_phone', '')
            )
            db.session.add(buyer_profile)
        
        db.session.commit()
        
        return jsonify({
            'message': 'User registered successfully',
            'user_id': new_user.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password required'}), 400
        
        user = User.query.filter_by(email=data['email']).first()
        
        if user and user.check_password(data['password']):
            access_token = create_access_token(
                identity=user.id,
                additional_claims={'user_type': user.user_type}
            )
            
            profile = None
            if user.user_type == 'farmer':
                profile = Farmer.query.filter_by(user_id=user.id).first()
            elif user.user_type == 'buyer':
                profile = Buyer.query.filter_by(user_id=user.id).first()
            
            return jsonify({
                'access_token': access_token,
                'user_id': user.id,
                'user_type': user.user_type,
                'profile': {
                    'id': profile.id,
                    'name': profile.farm_name if user.user_type == 'farmer' else profile.full_name
                } if profile else None
            }), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'error': 'Login failed'}), 500

# Farmer Profile Routes
@app.route('/api/farmers/<int:farmer_id>', methods=['GET'])
def get_farmer_profile(farmer_id):
    try:
        farmer = Farmer.query.get_or_404(farmer_id)
        
        avg_rating = db.session.query(db.func.avg(Review.rating)).filter(
            Review.farmer_id == farmer_id
        ).scalar() or 0
        
        profile_data = {
            'id': farmer.id,
            'farm_name': farmer.farm_name,
            'description': farmer.description,
            'address': farmer.address,
            'latitude': farmer.latitude,
            'longitude': farmer.longitude,
            'contact_phone': farmer.contact_phone,
            'contact_email': farmer.contact_email,
            'delivery_radius_km': farmer.delivery_radius_km,
            'is_verified': farmer.is_verified,
            'average_rating': round(float(avg_rating), 1),
            'total_reviews': len(farmer.reviews)
        }
        
        return jsonify(profile_data), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get farmer profile'}), 500

@app.route('/api/farmers/<int:farmer_id>/products', methods=['GET'])
def get_farmer_products(farmer_id):
    try:
        products = Product.query.filter_by(farmer_id=farmer_id, is_available=True).all()
        
        products_data = []
        for product in products:
            products_data.append({
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'category': product.category,
                'price_per_unit': product.price_per_unit,
                'unit_type': product.unit_type,
                'current_stock': product.current_stock,
                'image_url': product.image_url,
                'is_available': product.is_available
            })
        
        return jsonify(products_data), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get farmer products'}), 500

# Product Management Routes
@app.route('/api/products', methods=['POST'])
@jwt_required()
def create_product():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        farmer = Farmer.query.filter_by(user_id=current_user_id).first()
        if not farmer:
            return jsonify({'error': 'Farmer profile not found'}), 404
        
        required_fields = ['name', 'category', 'price_per_unit', 'unit_type', 'current_stock']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        new_product = Product(
            farmer_id=farmer.id,
            name=data['name'],
            description=data.get('description', ''),
            category=data['category'],
            price_per_unit=data['price_per_unit'],
            unit_type=data['unit_type'],
            current_stock=data['current_stock'],
            min_stock_alert=data.get('min_stock_alert', 0),
            image_url=data.get('image_url', '')
        )
        
        db.session.add(new_product)
        db.session.commit()
        
        return jsonify({
            'message': 'Product created successfully',
            'product_id': new_product.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create product'}), 500

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    try:
        current_user_id = get_jwt_identity()
        product = Product.query.get_or_404(product_id)
        
        farmer = Farmer.query.filter_by(user_id=current_user_id).first()
        if not farmer or product.farmer_id != farmer.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        
        updatable_fields = ['name', 'description', 'category', 'price_per_unit', 
                           'unit_type', 'current_stock', 'min_stock_alert', 
                           'is_available', 'image_url']
        
        for field in updatable_fields:
            if field in data:
                setattr(product, field, data[field])
        
        product.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'message': 'Product updated successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update product'}), 500

# Search and Discovery Routes
@app.route('/api/search/farmers', methods=['GET'])
def search_farmers():
    try:
        latitude = request.args.get('lat', type=float)
        longitude = request.args.get('lng', type=float)
        radius_km = request.args.get('radius', 50, type=float)
        category = request.args.get('category')
        search_query = request.args.get('q')
        
        farmers = Farmer.query.filter_by(is_verified=True)
        
        if category:
            farmers = farmers.join(Product).filter(Product.category == category, Product.is_available == True)
        
        if search_query:
            farmers = farmers.filter(
                Farmer.farm_name.ilike(f'%{search_query}%') |
                Farmer.description.ilike(f'%{search_query}%')
            )
        
        farmers = farmers.all()
        farmers_data = []
        
        for farmer in farmers:
            distance = None
            if latitude and longitude:
                distance = calculate_distance(latitude, longitude, farmer.latitude, farmer.longitude)
                if distance > radius_km:
                    continue
            
            avg_rating = db.session.query(db.func.avg(Review.rating)).filter(
                Review.farmer_id == farmer.id
            ).scalar() or 0
            
            categories = db.session.query(Product.category).filter(
                Product.farmer_id == farmer.id,
                Product.is_available == True
            ).distinct().all()
            
            farmer_data = {
                'id': farmer.id,
                'farm_name': farmer.farm_name,
                'description': farmer.description,
                'address': farmer.address,
                'latitude': farmer.latitude,
                'longitude': farmer.longitude,
                'contact_phone': farmer.contact_phone,
                'delivery_radius_km': farmer.delivery_radius_km,
                'average_rating': round(float(avg_rating), 1),
                'total_reviews': len(farmer.reviews),
                'categories': [cat[0] for cat in categories],
                'distance_km': round(distance, 2) if distance else None
            }
            
            farmers_data.append(farmer_data)
        
        return jsonify(farmers_data), 200
        
    except Exception as e:
        return jsonify({'error': 'Search failed'}), 500

@app.route('/api/search/products', methods=['GET'])
def search_products():
    try:
        latitude = request.args.get('lat', type=float)
        longitude = request.args.get('lng', type=float)
        radius_km = request.args.get('radius', 50, type=float)
        category = request.args.get('category')
        search_query = request.args.get('q')
        min_price = request.args.get('min_price', type=float)
        max_price = request.args.get('max_price', type=float)
        
        products = Product.query.filter_by(is_available=True).join(Farmer)
        
        if category:
            products = products.filter(Product.category == category)
        
        if search_query:
            products = products.filter(
                Product.name.ilike(f'%{search_query}%') |
                Product.description.ilike(f'%{search_query}%') |
                Farmer.farm_name.ilike(f'%{search_query}%')
            )
        
        if min_price is not None:
            products = products.filter(Product.price_per_unit >= min_price)
        
        if max_price is not None:
            products = products.filter(Product.price_per_unit <= max_price)
        
        products = products.all()
        products_data = []
        
        for product in products:
            distance = None
            if latitude and longitude:
                distance = calculate_distance(latitude, longitude, product.farmer.latitude, product.farmer.longitude)
                if distance > radius_km:
                    continue
            
            product_data = {
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'category': product.category,
                'price_per_unit': product.price_per_unit,
                'unit_type': product.unit_type,
                'current_stock': product.current_stock,
                'image_url': product.image_url,
                'farmer': {
                    'id': product.farmer.id,
                    'farm_name': product.farmer.farm_name,
                    'address': product.farmer.address,
                    'latitude': product.farmer.latitude,
                    'longitude': product.farmer.longitude
                },
                'distance_km': round(distance, 2) if distance else None
            }
            
            products_data.append(product_data)
        
        return jsonify(products_data), 200
        
    except Exception as e:
        return jsonify({'error': 'Search failed'}), 500

# Order Management Routes
@app.route('/api/orders', methods=['POST'])
@jwt_required()
def create_order():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        buyer = Buyer.query.filter_by(user_id=current_user_id).first()
        if not buyer:
            return jsonify({'error': 'Buyer profile not found'}), 404
        
        if 'items' not in data or not data['items']:
            return jsonify({'error': 'Order items required'}), 400
        
        first_product = Product.query.get(data['items'][0]['product_id'])
        if not first_product:
            return jsonify({'error': 'Invalid product'}), 400
        
        farmer_id = first_product.farmer_id
        
        total_amount = 0
        order_items = []
        
        for item_data in data['items']:
            product = Product.query.get(item_data['product_id'])
            if not product or product.farmer_id != farmer_id:
                return jsonify({'error': 'All products must be from the same farmer'}), 400
            
            if product.current_stock < item_data['quantity']:
                return jsonify({'error': f'Insufficient stock for {product.name}'}), 400
            
            item_total = product.price_per_unit * item_data['quantity']
            total_amount += item_total
            
            order_items.append({
                'product': product,
                'quantity': item_data['quantity'],
                'unit_price': product.price_per_unit,
                'total_price': item_total
            })
        
        new_order = Order(
            order_number=generate_order_number(),
            farmer_id=farmer_id,
            buyer_id=buyer.id,
            total_amount=total_amount,
            delivery_address=data.get('delivery_address', buyer.address),
            delivery_instructions=data.get('delivery_instructions'),
            delivery_date=data.get('delivery_date')
        )
        
        db.session.add(new_order)
        db.session.flush()
        
        for item in order_items:
            order_item = OrderItem(
                order_id=new_order.id,
                product_id=item['product'].id,
                quantity=item['quantity'],
                unit_price=item['unit_price'],
                total_price=item['total_price']
            )
            db.session.add(order_item)
            
            item['product'].current_stock -= item['quantity']
            item['product'].updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'message': 'Order created successfully',
            'order_id': new_order.id,
            'order_number': new_order.order_number
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create order'}), 500

@app.route('/api/orders', methods=['GET'])
@jwt_required()
def get_orders():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        orders = []
        if user.user_type == 'farmer':
            farmer = Farmer.query.filter_by(user_id=current_user_id).first()
            if farmer:
                orders = Order.query.filter_by(farmer_id=farmer.id).all()
        elif user.user_type == 'buyer':
            buyer = Buyer.query.filter_by(user_id=current_user_id).first()
            if buyer:
                orders = Order.query.filter_by(buyer_id=buyer.id).all()
        
        orders_data = []
        for order in orders:
            order_data = {
                'id': order.id,
                'order_number': order.order_number,
                'total_amount': order.total_amount,
                'status': order.status,
                'order_date': order.order_date.isoformat(),
                'delivery_date': order.delivery_date.isoformat() if order.delivery_date else None,
                'farmer_name': order.farmer.farm_name,
                'buyer_name': order.buyer.full_name
            }
            orders_data.append(order_data)
        
        return jsonify(orders_data), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get orders'}), 500

# Messaging System Routes
@app.route('/api/orders/<int:order_id>/messages', methods=['POST'])
@jwt_required()
def send_message(order_id):
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        order = Order.query.get_or_404(order_id)
        
        if user.user_type == 'farmer':
            farmer = Farmer.query.filter_by(user_id=current_user_id).first()
            if not farmer or order.farmer_id != farmer.id:
                return jsonify({'error': 'Unauthorized'}), 403
        elif user.user_type == 'buyer':
            buyer = Buyer.query.filter_by(user_id=current_user_id).first()
            if not buyer or order.buyer_id != buyer.id:
                return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        if 'message_text' not in data or not data['message_text'].strip():
            return jsonify({'error': 'Message text is required'}), 400
        
        new_message = Message(
            order_id=order_id,
            sender_id=current_user_id,
            sender_type=user.user_type,
            message_text=data['message_text'].strip()
        )
        
        db.session.add(new_message)
        db.session.commit()
        
        return jsonify({
            'message': 'Message sent successfully',
            'message_id': new_message.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to send message'}), 500

@app.route('/api/orders/<int:order_id>/messages', methods=['GET'])
@jwt_required()
def get_messages(order_id):
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        order = Order.query.get_or_404(order_id)
        
        if user.user_type == 'farmer':
            farmer = Farmer.query.filter_by(user_id=current_user_id).first()
            if not farmer or order.farmer_id != farmer.id:
                return jsonify({'error': 'Unauthorized'}), 403
        elif user.user_type == 'buyer':
            buyer = Buyer.query.filter_by(user_id=current_user_id).first()
            if not buyer or order.buyer_id != buyer.id:
                return jsonify({'error': 'Unauthorized'}), 403
        
        messages = Message.query.filter_by(order_id=order_id).order_by(Message.created_at.asc()).all()
        
        messages_data = []
        for message in messages:
            messages_data.append({
                'id': message.id,
                'sender_id': message.sender_id,
                'sender_type': message.sender_type,
                'message_text': message.message_text,
                'is_read': message.is_read,
                'created_at': message.created_at.isoformat()
            })
        
        return jsonify(messages_data), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get messages'}), 500

# Review and Rating System Routes
@app.route('/api/reviews', methods=['POST'])
@jwt_required()
def create_review():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        buyer = Buyer.query.filter_by(user_id=current_user_id).first()
        if not buyer:
            return jsonify({'error': 'Buyer profile not found'}), 404
        
        required_fields = ['farmer_id', 'order_id', 'rating']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        order = Order.query.filter_by(id=data['order_id'], buyer_id=buyer.id).first()
        if not order:
            return jsonify({'error': 'Order not found'}), 404
        
        existing_review = Review.query.filter_by(order_id=data['order_id']).first()
        if existing_review:
            return jsonify({'error': 'Review already exists for this order'}), 400
        
        if not 1 <= data['rating'] <= 5:
            return jsonify({'error': 'Rating must be between 1 and 5'}), 400
        
        new_review = Review(
            farmer_id=data['farmer_id'],
            buyer_id=buyer.id,
            order_id=data['order_id'],
            rating=data['rating'],
            comment=data.get('comment', '')
        )
        
        db.session.add(new_review)
        db.session.commit()
        
        return jsonify({
            'message': 'Review created successfully',
            'review_id': new_review.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create review'}), 500

@app.route('/api/farmers/<int:farmer_id>/reviews', methods=['GET'])
def get_farmer_reviews(farmer_id):
    try:
        reviews = Review.query.filter_by(farmer_id=farmer_id).order_by(Review.created_at.desc()).all()
        
        reviews_data = []
        for review in reviews:
            reviews_data.append({
                'id': review.id,
                'rating': review.rating,
                'comment': review.comment,
                'buyer_name': review.buyer.full_name,
                'created_at': review.created_at.isoformat()
            })
        
        return jsonify(reviews_data), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get reviews'}), 500

# Availability Calendar Routes
@app.route('/api/farmers/<int:farmer_id>/availability', methods=['POST'])
@jwt_required()
def set_availability(farmer_id):
    try:
        current_user_id = get_jwt_identity()
        farmer = Farmer.query.get_or_404(farmer_id)
        
        if farmer.user_id != current_user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        
        required_fields = ['product_id', 'date', 'available_quantity']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Check if product belongs to farmer
        product = Product.query.filter_by(id=data['product_id'], farmer_id=farmer_id).first()
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        
        availability = AvailabilityCalendar(
            farmer_id=farmer_id,
            product_id=data['product_id'],
            date=datetime.strptime(data['date'], '%Y-%m-%d').date(),
            available_quantity=data['available_quantity'],
            is_available=data.get('is_available', True)
        )
        
        db.session.add(availability)
        db.session.commit()
        
        return jsonify({'message': 'Availability set successfully'}), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to set availability'}), 500

# Map Interface Routes
@app.route('/api/map/farmers', methods=['GET'])
def get_map_farmers():
    try:
        latitude = request.args.get('lat', type=float)
        longitude = request.args.get('lng', type=float)
        radius_km = request.args.get('radius', 50, type=float)
        
        farmers = Farmer.query.filter_by(is_verified=True).all()
        
        map_data = []
        for farmer in farmers:
            distance = None
            if latitude and longitude:
                distance = calculate_distance(latitude, longitude, farmer.latitude, farmer.longitude)
                if distance > radius_km:
                    continue
            
            avg_rating = db.session.query(db.func.avg(Review.rating)).filter(
                Review.farmer_id == farmer.id
            ).scalar() or 0
            
            categories = db.session.query(Product.category).filter(
                Product.farmer_id == farmer.id,
                Product.is_available == True
            ).distinct().all()
            
            farmer_data = {
                'id': farmer.id,
                'farm_name': farmer.farm_name,
                'latitude': farmer.latitude,
                'longitude': farmer.longitude,
                'address': farmer.address,
                'delivery_radius_km': farmer.delivery_radius_km,
                'average_rating': round(float(avg_rating), 1),
                'categories': [cat[0] for cat in categories],
                'distance_km': round(distance, 2) if distance else None
            }
            
            map_data.append(farmer_data)
        
        return jsonify(map_data), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get map data'}), 500

# Inventory Management Routes
@app.route('/api/farmers/<int:farmer_id>/inventory', methods=['GET'])
@jwt_required()
def get_inventory(farmer_id):
    try:
        current_user_id = get_jwt_identity()
        farmer = Farmer.query.get_or_404(farmer_id)
        
        if farmer.user_id != current_user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        products = Product.query.filter_by(farmer_id=farmer_id).all()
        
        inventory_data = []
        for product in products:
            total_sold = db.session.query(db.func.sum(OrderItem.quantity)).filter(
                OrderItem.product_id == product.id,
                Order.order_date >= datetime.utcnow().replace(day=1)  # This month
            ).join(Order).scalar() or 0
            
            inventory_data.append({
                'id': product.id,
                'name': product.name,
                'category': product.category,
                'current_stock': product.current_stock,
                'min_stock_alert': product.min_stock_alert,
                'is_available': product.is_available,
                'total_sold_this_month': total_sold,
                'needs_restock': product.current_stock <= product.min_stock_alert
            })
        
        return jsonify(inventory_data), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get inventory'}), 500

# Initialize Database
@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)