"""
BookMyShow Application - Single File Backend
Following System Design Principles:
- Separation of Concerns (Models, Services, Controllers)
- Single Responsibility Principle
- DRY (Don't Repeat Yourself)
- Proper Error Handling
- Caching Strategy
"""

from flask import Flask, request, jsonify, session, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_caching import Cache
from datetime import datetime, timedelta
import uuid
import os
from flask_cors import CORS
from flask_session import Session

from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash


# ==================== CONFIGURATION ====================

app = Flask(__name__)
app.config.update(
    SESSION_TYPE="filesystem",   # production-safe
    SESSION_PERMANENT=False,
    SESSION_USE_SIGNER=True,
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=True
)

Session(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secret-key-change-in-production')
db_url = os.environ.get('DATABASE_URL', 'sqlite:///bookmyshow.db')
if db_url.startswith("postgres"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Cache configuration
app.config['CACHE_TYPE'] = 'SimpleCache'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300  # 5 minutes





CORS(
    app,
    supports_credentials=True,
    resources={r"/*": {
        "origins": [
            "https://bms-frontend-three.vercel.app"
        ]
    }}
)




# Cache timeout constants
CACHE_TIMEOUT_SHOWS = 300  # 5 minutes
CACHE_TIMEOUT_SEATS = 60   # 1 minute
CACHE_TIMEOUT_BOOKINGS = 180  # 3 minutes

db = SQLAlchemy(app)


cache = Cache(app)


# ==================== MODELS (Data Layer) ====================

class User(db.Model):
    """User model"""
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    city = db.Column(db.String(80))

    def set_password(self, pwd):
        """Set user password with hashing"""
        self.password = generate_password_hash(pwd)

    def check_password(self, pwd):
        """Check if password matches"""
        return check_password_hash(self.password, pwd)


class Theater(db.Model):
    """Theater model"""
    __tablename__ = 'theater'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    city = db.Column(db.String(80), nullable=False)
    address = db.Column(db.String(200))
    
    # Relationships
    shows = db.relationship('Show', backref='theater', lazy=True, cascade='all, delete-orphan')


class Show(db.Model):
    """Show model"""
    __tablename__ = 'show'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    theater_id = db.Column(db.Integer, db.ForeignKey('theater.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    price = db.Column(db.Float, nullable=False)
    
    # Relationships
    seats = db.relationship('Seat', backref='show', lazy=True, cascade='all, delete-orphan')
    bookings = db.relationship('Booking', backref='show', lazy=True)


class Seat(db.Model):
    """Seat model"""
    __tablename__ = 'seat'
    
    id = db.Column(db.Integer, primary_key=True)
    show_id = db.Column(db.Integer, db.ForeignKey('show.id'), nullable=False)
    seat_number = db.Column(db.String(10), nullable=False)
    is_booked = db.Column(db.Boolean, default=False, nullable=False)
    
    # Relationships
    bookings = db.relationship('Booking', backref='seat', lazy=True)


class Booking(db.Model):
    """Booking model"""
    __tablename__ = 'booking'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    show_id = db.Column(db.Integer, db.ForeignKey('show.id'), nullable=False)
    seat_id = db.Column(db.Integer, db.ForeignKey('seat.id'), nullable=False)
    payment_status = db.Column(db.String(20), default='pending', nullable=False)
    booking_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    ticket = db.relationship('Ticket', backref='booking', uselist=False, lazy=True)


class Ticket(db.Model):
    """Ticket model"""
    __tablename__ = 'ticket'
    
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('booking.id'), nullable=False, unique=True)
    ticket_code = db.Column(db.String(20), unique=True, nullable=False)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


# ==================== EXCEPTIONS ====================

class BookMyShowException(Exception):
    """Base exception for BookMyShow application"""
    def __init__(self, message, status_code=400):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class NotFoundError(BookMyShowException):
    """Raised when a resource is not found"""
    def __init__(self, message):
        super().__init__(message, status_code=404)


class BusinessLogicError(BookMyShowException):
    """Raised when business logic validation fails"""
    def __init__(self, message):
        super().__init__(message, status_code=400)


# ==================== SERVICE LAYER (Business Logic) ====================

class ShowService:
    """Service for show-related business logic"""
    
    @staticmethod
    def get_all_cities():
        """Get all available cities"""
        cities = db.session.query(Theater.city).distinct().all()
        return [city[0] for city in cities]
    
    @staticmethod
    def get_shows_by_city(city):
        """Get shows by city with caching"""
        cache_key = f'shows_{city}'
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return cached_data
        
        shows_query = (
    db.session.query(Show, Theater)
    .join(Theater, Show.theater_id == Theater.id)
    .filter(Theater.city == city)
    .filter(Show.start_time > datetime.now())
    .order_by(Show.start_time)
    .all()
)


        shows_data = [
            {
                'show_id': show.id,
                'movie': show.name,
                'theater': theater.name,
                'theater_address': theater.address,
                'time': show.start_time.strftime('%Y-%m-%d %H:%M'),
                'end_time': show.end_time.strftime('%Y-%m-%d %H:%M'),
                'price': show.price
            }
            for show, theater in shows_query
        ]
        
        cache.set(cache_key, shows_data, timeout=CACHE_TIMEOUT_SHOWS)
        return shows_data
   
    
    @staticmethod
    def get_show_details(show_id):
        """Get show details with seats"""
        show = Show.query.get(show_id)
        if not show:
            raise NotFoundError(f'Show with ID {show_id} not found')
        
        theater = Theater.query.get(show.theater_id)
        if not theater:
            raise NotFoundError(f'Theater for show {show_id} not found')
        
        # Cache seat availability
        cache_key = f'seats_{show_id}'
        seats_data = cache.get(cache_key)
        
        if seats_data is None:
            seats = Seat.query.filter_by(show_id=show_id).order_by(Seat.seat_number).all()
            seats_data = [
                {'id': seat.id, 'seat': seat.seat_number, 'booked': seat.is_booked}
                for seat in seats
            ]
            cache.set(cache_key, seats_data, timeout=CACHE_TIMEOUT_SEATS)
        
        return {
            'show': {
                'id': show.id,
                'movie': show.name,
                'theater': theater.name,
                'theater_address': theater.address,
                'time': show.start_time.strftime('%Y-%m-%d %H:%M'),
                'end_time': show.end_time.strftime('%Y-%m-%d %H:%M'),
                'price': show.price
            },
            'seats': seats_data
        }
    
    @staticmethod
    def invalidate_caches(show_id=None, city=None):
        """Invalidate relevant caches"""
        if show_id:
            cache.delete(f'seats_{show_id}')
        if city:
            cache.delete(f'shows_{city}')


class BookingService:
    """Service for booking-related business logic"""
    
    @staticmethod
    def create_booking(user_id, show_id, seat_id):
        """Create a new booking"""
        # Validate seat exists and is available
        seat = Seat.query.get(seat_id)
        if not seat:
            raise NotFoundError('Seat not found')
        
        if seat.is_booked:
            ShowService.invalidate_caches(show_id=show_id)
            raise BusinessLogicError('Seat already booked. Please select another seat.')
        
        # Validate show exists
        show = Show.query.get(show_id)
        if not show:
            raise NotFoundError('Show not found')
        
        # Create booking
        booking = Booking(
            user_id=user_id,
            show_id=show_id,
            seat_id=seat_id
        )
        
        db.session.add(booking)
        db.session.commit()

        # Clear cache
        ShowService.invalidate_caches(show_id=show_id)
        
        return booking
    
    @staticmethod
    def get_booking_details(booking_id):
        """Get booking details"""
        booking = Booking.query.get(booking_id)
        if not booking:
            raise NotFoundError(f'Booking with ID {booking_id} not found')
        
        show = Show.query.get(booking.show_id)
        seat = Seat.query.get(booking.seat_id)
        theater = Theater.query.get(show.theater_id)
        
        if not all([show, seat, theater]):
            raise NotFoundError('Booking details incomplete')
        
        return {
            'id': booking.id,
            'movie': show.name,
            'theater': theater.name,
            'seat': seat.seat_number,
            'time': show.start_time.strftime('%Y-%m-%d %H:%M'),
            'price': show.price
        }
    
    @staticmethod
    def get_user_bookings(user_id):
        """Get all bookings for a user"""
        cache_key = f'bookings_{user_id}'
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return cached_data
        
        bookings = Booking.query.filter_by(user_id=user_id).order_by(Booking.booking_time.desc()).all()
        bookings_data = []
        
        for booking in bookings:
            show = Show.query.get(booking.show_id)
            seat = Seat.query.get(booking.seat_id)
            theater = Theater.query.get(show.theater_id)
            ticket = Ticket.query.filter_by(booking_id=booking.id).first()
            
            bookings_data.append({
                'booking_id': booking.id,
                'movie': show.name,
                'theater': theater.name,
                'seat': seat.seat_number,
                'time': show.start_time.strftime('%Y-%m-%d %H:%M'),
                'status': booking.payment_status,
                'ticket_code': ticket.ticket_code if ticket else None,
                'booking_time': booking.booking_time.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        cache.set(cache_key, bookings_data, timeout=CACHE_TIMEOUT_BOOKINGS)
        return bookings_data
    
    @staticmethod
    def invalidate_user_bookings_cache(user_id):
        """Invalidate cache for user bookings"""
        cache.delete(f'bookings_{user_id}')


class AuthService:
    """Service for authentication-related business logic"""
    
    @staticmethod
    def register_user(username, email, password, city=None):
        """Register a new user"""
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            raise BusinessLogicError('Email already registered')
        
        if User.query.filter_by(username=username).first():
            raise BusinessLogicError('Username already taken')
        
        # Create new user
        user = User(
            username=username,
            email=email,
            city=city
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        return user
    
    @staticmethod
    def login_user(email, password):
        """Authenticate user"""
        user = User.query.filter_by(email=email).first()
        
        if not user or not user.check_password(password):
            raise BusinessLogicError('Invalid email or password')
        
        return user
    
    @staticmethod
    def get_current_user():
        """Get current logged in user"""
        user_id = session.get('user_id')
        if not user_id:
            return None
        return User.query.get(user_id)


class PaymentService:
    """Service for payment-related business logic"""
    
    @staticmethod
    def confirm_payment(booking_id):
        """Confirm payment and generate ticket"""
        booking = Booking.query.get(booking_id)
        if not booking:
            raise NotFoundError(f'Booking with ID {booking_id} not found')
        
        # Check if already confirmed
        if booking.payment_status == 'confirmed':
            ticket = Ticket.query.filter_by(booking_id=booking_id).first()
            if ticket:
                return ticket.ticket_code
            raise BusinessLogicError('Payment already confirmed but ticket not found')
        
        # Mark seat as booked
        seat = Seat.query.get(booking.seat_id)
        seat.is_booked = True
        
        # Update booking status
        booking.payment_status = 'confirmed'
        
        # Generate ticket
        ticket = Ticket(
            booking_id=booking.id,
            ticket_code=str(uuid.uuid4())[:8].upper()
        )
        
        db.session.add(ticket)
        db.session.commit()
        
        # Clear relevant caches
        show = Show.query.get(booking.show_id)
        theater = Theater.query.get(show.theater_id)
        ShowService.invalidate_caches(show_id=booking.show_id, city=theater.city)
        BookingService.invalidate_user_bookings_cache(booking.user_id)
        
        return ticket.ticket_code
    
    @staticmethod
    def get_ticket_details(booking_id):
        """Get ticket details"""
        booking = Booking.query.get(booking_id)
        if not booking:
            raise NotFoundError(f'Booking with ID {booking_id} not found')
        
        ticket = Ticket.query.filter_by(booking_id=booking_id).first()
        if not ticket:
            raise NotFoundError('Ticket not found')
        
        show = Show.query.get(booking.show_id)
        seat = Seat.query.get(booking.seat_id)
        theater = Theater.query.get(show.theater_id)
        
        return {
            'code': ticket.ticket_code,
            'movie': show.name,
            'theater': theater.name,
            'theater_address': theater.address,
            'seat': seat.seat_number,
            'time': show.start_time.strftime('%Y-%m-%d %H:%M'),
            'end_time': show.end_time.strftime('%Y-%m-%d %H:%M'),
            'price': show.price,
            'booking_time': booking.booking_time.strftime('%Y-%m-%d %H:%M:%S')
        }


# ==================== ERROR HANDLING ====================

def handle_exceptions(f):
    """Decorator for error handling"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except NotFoundError as e:
            return jsonify({'error': e.message}), e.status_code
        except BusinessLogicError as e:
            return jsonify({'error': e.message}), e.status_code
        except BookMyShowException as e:
            return jsonify({'error': e.message}), e.status_code
        except Exception as e:
            return jsonify({'error': 'Internal server error', 'details': str(e)}), 500
    return decorated_function


def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Please login to continue'}), 401
        return f(*args, **kwargs)
    return decorated_function


# ==================== ROUTES (Controller Layer) ====================




@app.route('/api/auth/register', methods=['POST'])
@handle_exceptions
def api_register():
    """Register a new user"""
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password are required'}), 400
    
    user = AuthService.register_user(
        username=data.get('username', data.get('email').split('@')[0]),
        email=data.get('email'),
        password=data.get('password'),
        city=data.get('city')
    )
    
    # Auto login after registration
    session['user_id'] = user.id
    session['username'] = user.username
    
    return jsonify({
        'message': 'Registration successful',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email
        }
    }), 201


@app.route('/api/auth/login', methods=['POST'])
@handle_exceptions
def api_login():
    """Login user"""
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password are required'}), 400
    
    user = AuthService.login_user(
        email=data.get('email'),
        password=data.get('password')
    )
    session.clear()
    session.modified = True
    session['user_id'] = user.id
    session['username'] = user.username

    
    return jsonify({
        'message': 'Login successful',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email
        }
    })


@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    """Logout user"""
    session.clear()
    return jsonify({'message': 'Logged out successfully'})


@app.route('/api/auth/me', methods=['GET'])
@handle_exceptions
def api_get_current_user():
    """Get current logged in user"""
    user = AuthService.get_current_user()
    if not user:
        return jsonify({'error': 'Not logged in'}), 401

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'city': user.city
    })


@app.route('/api/cities', methods=['GET'])
@handle_exceptions
def api_cities():
    """API endpoint for cities list"""
    cities = ShowService.get_all_cities()
    return jsonify(cities)


@app.route('/api/shows/city/<city>', methods=['GET'])
@handle_exceptions
def api_shows_by_city(city):
    """API endpoint for shows by city"""
    shows_data = ShowService.get_shows_by_city(city)
    return jsonify(shows_data)


@app.route('/api/show/<int:show_id>', methods=['GET'])
@handle_exceptions
def api_show_details(show_id):
    """API endpoint for show details with seats"""
    show_data = ShowService.get_show_details(show_id)
    return jsonify(show_data)


@app.route('/api/seats/<int:show_id>', methods=['GET'])
@handle_exceptions
def api_seats(show_id):
    """API endpoint for seat availability"""
    show_data = ShowService.get_show_details(show_id)
    return jsonify(show_data['seats'])


@app.route('/book', methods=['POST'])
@handle_exceptions
@login_required
def book_seat():
    """Book a seat - returns JSON"""
    show_id = request.form.get('show_id')
    seat_id = request.form.get('seat_id')
    
    if not show_id or not seat_id:
        return jsonify({'error': 'Please select a seat'}), 400
    
    try:
        show_id = int(show_id)
        seat_id = int(seat_id)
    except ValueError:
        return jsonify({'error': 'Invalid show_id or seat_id'}), 400
    
    user_id = session.get('user_id')
    booking = BookingService.create_booking(user_id, show_id, seat_id)
    
    return jsonify({
        'booking_id': booking.id,
        'message': 'Seat booked successfully'
    })


@app.route('/api/booking/<int:booking_id>', methods=['GET'])
@handle_exceptions
def api_booking_details(booking_id):
    """API endpoint for booking details"""
    booking_info = BookingService.get_booking_details(booking_id)
    return jsonify(booking_info)


@app.route('/confirm_payment/<int:booking_id>', methods=['POST'])
@handle_exceptions
def confirm_payment(booking_id):
    """Confirm payment and generate ticket - returns JSON"""
    ticket_code = PaymentService.confirm_payment(booking_id)
    return jsonify({
        'ticket_code': ticket_code,
        'message': 'Payment successful'
    })


@app.route('/api/ticket/<int:booking_id>', methods=['GET'])
@handle_exceptions
def api_ticket_details(booking_id):
    """API endpoint for ticket details"""
    ticket_info = PaymentService.get_ticket_details(booking_id)
    return jsonify(ticket_info)


@app.route('/api/profile/bookings', methods=['GET'])
@handle_exceptions
@login_required
def api_profile_bookings():
    """API endpoint for user bookings"""
    user_id = session.get('user_id')
    bookings_data = BookingService.get_user_bookings(user_id)
    return jsonify(bookings_data)


# ==================== DATA INITIALIZATION ====================

def init_data():
    """Initialize sample data with more cities and event types"""
    if Theater.query.first():
        return

    # Create theaters in different Indian cities
    cities_data = [
        # Mumbai
        {'name': 'INOX Cinemas', 'city': 'Mumbai', 'address': 'Phoenix Mall, Kurla'},
        {'name': 'PVR Cinemas', 'city': 'Mumbai', 'address': 'High Street Phoenix, Lower Parel'},
        {'name': 'Cinepolis', 'city': 'Mumbai', 'address': 'R City Mall, Ghatkopar'},

        # Delhi
        {'name': 'Cinepolis', 'city': 'Delhi', 'address': 'Select Citywalk, Saket'},
        {'name': 'INOX', 'city': 'Delhi', 'address': 'DLF Promenade, Vasant Kunj'},
        {'name': 'PVR', 'city': 'Delhi', 'address': 'Ambience Mall, Gurgaon'},

        # Bangalore
        {'name': 'PVR', 'city': 'Bangalore', 'address': 'Orion Mall, Malleswaram'},
        {'name': 'INOX', 'city': 'Bangalore', 'address': 'Forum Mall, Koramangala'},
        {'name': 'Cinepolis', 'city': 'Bangalore', 'address': 'Mantri Square Mall'},

        # Chennai
        {'name': 'PVR Cinemas', 'city': 'Chennai', 'address': 'Express Avenue Mall'},
        {'name': 'INOX', 'city': 'Chennai', 'address': 'Phoenix Market City'},

        # Hyderabad
        {'name': 'PVR', 'city': 'Hyderabad', 'address': 'Inorbit Mall, Cyberabad'},
        {'name': 'INOX', 'city': 'Hyderabad', 'address': 'GVK One Mall'},

        # Pune
        {'name': 'Cinepolis', 'city': 'Pune', 'address': 'Phoenix Market City'},
        {'name': 'PVR', 'city': 'Pune', 'address': 'Westend Mall'},

        # Kolkata
        {'name': 'INOX', 'city': 'Kolkata', 'address': 'South City Mall'},
        {'name': 'PVR', 'city': 'Kolkata', 'address': 'Quest Mall'},

        # Coimbatore
        {'name': 'INOX', 'city': 'Coimbatore', 'address': 'Brookefields Mall'},

        # Jaipur
        {'name': 'PVR', 'city': 'Jaipur', 'address': 'World Trade Park'},

        # Ahmedabad
        {'name': 'INOX', 'city': 'Ahmedabad', 'address': 'Alpha One Mall'},

        # New cities
        {'name': 'PVR', 'city': 'Lucknow', 'address': 'Phoenix Palassio'},
        {'name': 'Cinepolis', 'city': 'Nagpur', 'address': 'Trillium Mall'},
        {'name': 'INOX', 'city': 'Surat', 'address': 'VR Surat'},
        {'name': 'PVR', 'city': 'Indore', 'address': 'Treasure Island Mall'},
        {'name': 'INOX', 'city': 'Vizag', 'address': 'Cmr Central Mall'},
        {'name': 'Cinepolis', 'city': 'Noida', 'address': 'DLF Mall of India'},
    ]

    theaters = []
    for theater_data in cities_data:
        theater = Theater(**theater_data)
        db.session.add(theater)
        theaters.append(theater)

    db.session.commit()

    # Event catalog: movies, concerts, exhibitions
    movie_titles = [
        # Bollywood
        'Dangal', 'Baahubali 2', 'PK', '3 Idiots', 'Lagaan',
        'Dilwale Dulhania Le Jayenge', 'Kabir Singh', 'War', 'Tiger Zinda Hai',
        # Hollywood
        'Interstellar', 'Inception', 'The Dark Knight', 'Avatar', 'Titanic',
        'Avengers: Endgame', 'Dune', 'Oppenheimer', 'Barbie', 'Spider-Man: No Way Home'
    ]

    concert_titles = [
        'Arijit Singh Live in Concert',
        'A. R. Rahman Musical Night',
        'Sunburn EDM Festival',
        'Bollywood Beats Live',
        'Coke Studio Live Tour',
        'Classical Evenings with Shankar Mahadevan',
        'Indie Rock Night',
        'Strings of India – Fusion Concert',
        'Retro Bollywood Night',
        'Global DJ Night'
    ]

    exhibition_titles = [
        'Modern Art Expo',
        'Photography Festival',
        'Auto Expo – Cars & Bikes',
        'Tech & Startup Expo',
        'Handicraft & Handloom Fair',
        'Book Fair & Literary Fest',
        'Science Exhibition for Students',
        'Food & Culture Festival',
        'Interior Design Exhibition',
        'Education & Career Fair'
    ]

    import random

    for theater in theaters:
        # Create 3–6 events per theater (mix of movies, concerts, exhibitions)
        num_events = random.randint(3, 6)
        for _ in range(num_events):
            category = random.choice(['movie', 'concert', 'exhibition'])

            if category == 'movie':
                name = random.choice(movie_titles)
                base_price_choices = [200, 250, 300, 350, 400]
            elif category == 'concert':
                name = random.choice(concert_titles)
                base_price_choices = [500, 750, 1000, 1500]
            else:  # exhibition
                name = random.choice(exhibition_titles)
                base_price_choices = [150, 200, 250, 300]

            start_time = datetime.now() + timedelta(
                days=random.randint(0, 10),
                hours=random.randint(10, 22)
            )
            # Movies ~3 hours, concerts ~2.5 hours, exhibitions ~4 hours
            if category == 'movie':
                duration_hours = 3
            elif category == 'concert':
                duration_hours = 2.5
            else:
                duration_hours = 4

            end_time = start_time + timedelta(hours=duration_hours)

            show = Show(
                name=name,
                theater_id=theater.id,
                start_time=start_time,
                end_time=end_time,
                price=random.choice(base_price_choices)
            )
            db.session.add(show)
            db.session.flush()

            # Create seats (more seats for concerts/exhibitions if you want)
            rows = ['A', 'B']
            if category in ['concert', 'exhibition']:
                rows = ['A', 'B', 'C']  # a bit larger capacity

            for row in rows:
                for num in range(1, 11):  # 10 seats per row
                    seat = Seat(show_id=show.id, seat_number=f'{row}{num}')
                    db.session.add(seat)

    db.session.commit()
    print("Sample data initialized successfully with movies, concerts and exhibitions!")



# ==================== APPLICATION INITIALIZATION ====================
with app.app_context():
    db.create_all()
    init_data()
