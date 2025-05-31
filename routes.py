from flask import render_template, request, redirect, url_for, flash, session, jsonify, abort
from app import app, db
from models import User, OTPProvider, OTPRequest, Message, Payment, AuditLog, SystemSettings, FacebookConfig
from auth import login_required, admin_required, get_current_user, log_action
from datetime import datetime, timedelta
import uuid

# Import optional modules
try:
    from otp_providers import OTPProviderManager
except ImportError:
    print("OTP providers module not found, some features may not work")
    OTPProviderManager = None

try:
    from utils import rate_limit_check, validate_phone_number, generate_api_response
except ImportError:
    print("Utils module not found, using basic implementations")
    def rate_limit_check(user_id, action, limit=10):
        return True
    def validate_phone_number(phone):
        return len(phone) > 5
    def generate_api_response(success, message, data=None, status_code=200):
        from flask import jsonify
        response = {'success': success, 'message': message}
        if data:
            response['data'] = data
        return jsonify(response), status_code

# Import Facebook authentication
try:
    from facebook_auth import facebook_bp
    app.register_blueprint(facebook_bp, url_prefix='/auth')
except ImportError:
    print("Facebook auth module not found, Facebook login will not be available")

# Make get_current_user available in templates
@app.context_processor
def inject_user():
    from datetime import datetime
    return dict(
        get_current_user=get_current_user, 
        moment=datetime.utcnow(),
        now=datetime.utcnow()
    )

@app.before_request
def make_session_permanent():
    session.permanent = True

@app.route('/')
def index():
    user = get_current_user()
    if user:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Get Facebook config for template
    facebook_config = FacebookConfig.get_config()

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html', facebook_config=facebook_config)

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password) and user.is_active:

            # Check device binding for premium users
            device_id = request.headers.get('User-Agent', '')
            ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))

            if user.is_premium and user.device_id and user.device_id != device_id:
                flash('Account is bound to another device. Contact admin for assistance.', 'error')
                log_action(user.id, 'device_mismatch', f'Device binding violation for user {username}', 'warning')
                return render_template('login.html')

            # Update user login info
            user.device_id = device_id
            user.ip_address = ip_address
            user.last_login = datetime.utcnow()
            db.session.commit()

            session['user_id'] = user.id
            session['is_admin'] = user.is_admin

            log_action(user.id, 'login_success', f'User {username} logged in successfully')
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials or account disabled', 'error')
            if user:
                log_action(user.id, 'login_failed', f'Failed login attempt for user {username}', 'warning')

    return render_template('login.html', facebook_config=facebook_config)

@app.route('/logout')
@login_required
def logout():
    user = get_current_user()
    if user:
        log_action(user.id, 'logout', f'User {user.username} logged out')
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()

    # Get recent OTP requests
    recent_requests = OTPRequest.query.filter_by(user_id=user.id)\
        .order_by(OTPRequest.created_at.desc()).limit(10).all()

    # Get unread messages
    unread_messages = Message.query.filter_by(recipient_id=user.id, is_read=False).count()

    # Get system stats for admins
    stats = {}
    if user.is_admin:
        stats = {
            'total_users': User.query.count(),
            'premium_users': User.query.filter_by(is_premium=True).count(),
            'total_requests': OTPRequest.query.count(),
            'pending_payments': Payment.query.filter_by(status='pending').count()
        }

    return render_template('dashboard.html', 
                         user=user, 
                         recent_requests=recent_requests,
                         unread_messages=unread_messages,
                         stats=stats)

@app.route('/otp-services')
@login_required
def otp_services():
    user = get_current_user()

    # Get available providers
    if user.is_premium:
        providers = OTPProvider.query.filter_by(is_active=True).all()
    else:
        providers = OTPProvider.query.filter_by(is_active=True, is_premium_only=False).all()

    return render_template('otp_services.html', user=user, providers=providers)

@app.route('/request-otp', methods=['POST'])
@login_required
def request_otp():
    user = get_current_user()

    phone_number = request.form.get('phone_number', '').strip()
    provider_id = request.form.get('provider_id', type=int)

    if not phone_number or not provider_id:
        flash('Phone number and provider are required', 'error')
        return redirect(url_for('otp_services'))

    # Validate phone number
    if not validate_phone_number(phone_number):
        flash('Invalid phone number format', 'error')
        return redirect(url_for('otp_services'))

    # Check rate limiting
    if not rate_limit_check(user.id, 'otp_request', limit=10):
        flash('Rate limit exceeded. Please wait before making another request.', 'error')
        return redirect(url_for('otp_services'))

    provider = OTPProvider.query.get(provider_id)
    if not provider or not provider.is_active:
        flash('Invalid or inactive provider', 'error')
        return redirect(url_for('otp_services'))

    # Check if provider requires premium
    if provider.is_premium_only and not user.is_subscription_active():
        flash('This provider requires a premium subscription', 'error')
        return redirect(url_for('premium'))

    # Check balance
    if user.balance < provider.cost_per_request:
        flash('Insufficient balance for this request', 'error')
        return redirect(url_for('dashboard'))

    # Create OTP request
    otp_request = OTPRequest(
        user_id=user.id,
        provider_id=provider.id,
        phone_number=phone_number,
        ip_address=request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR')),
        user_agent=request.headers.get('User-Agent', '')
    )

    db.session.add(otp_request)
    db.session.commit()

    # Process OTP request
    otp_manager = OTPProviderManager()
    try:
        result = otp_manager.request_otp(provider.name, phone_number)

        if result['success']:
            otp_request.status = 'success'
            otp_request.otp_code = result.get('otp_code')
            otp_request.response_data = str(result.get('data', ''))
            otp_request.cost = provider.cost_per_request
            otp_request.completed_at = datetime.utcnow()

            # Deduct balance
            user.balance -= provider.cost_per_request

            # Update provider stats
            provider.total_requests += 1
            provider.successful_requests += 1
            provider.update_success_rate()

            flash(f'OTP requested successfully! Code: {result.get("otp_code", "Check SMS")}', 'success')
            log_action(user.id, 'otp_success', f'OTP requested for {phone_number} via {provider.name}')
        else:
            otp_request.status = 'failed'
            otp_request.error_message = result.get('error', 'Unknown error')
            otp_request.completed_at = datetime.utcnow()

            provider.total_requests += 1
            provider.update_success_rate()

            flash(f'OTP request failed: {result.get("error", "Unknown error")}', 'error')
            log_action(user.id, 'otp_failed', f'OTP request failed for {phone_number} via {provider.name}', 'warning')

    except Exception as e:
        otp_request.status = 'failed'
        otp_request.error_message = str(e)
        otp_request.completed_at = datetime.utcnow()

        provider.total_requests += 1
        provider.update_success_rate()

        flash('OTP request failed due to system error', 'error')
        log_action(user.id, 'otp_error', f'System error during OTP request: {str(e)}', 'error')

    db.session.commit()
    return redirect(url_for('otp_services'))

@app.route('/disclaimer')
def disclaimer():
    """Halaman Disclaimer"""
    return render_template('disclaimer.html')

@app.route('/privacy')
def privacy():
    """Halaman Kebijakan Privasi"""
    return render_template('privacy.html')

@app.route('/data-deletion')
def data_deletion():
    """Halaman Penghapusan Data Pengguna"""
    return render_template('data_deletion.html')

@app.route('/premium')
@login_required
def premium():
    user = get_current_user()
    return render_template('premium.html', user=user)

@app.route('/submit-payment', methods=['POST'])
@login_required
def submit_payment():
    user = get_current_user()

    amount = request.form.get('amount', type=float)
    payment_method = request.form.get('payment_method', '').strip()
    transaction_id = request.form.get('transaction_id', '').strip()
    subscription_type = request.form.get('subscription_type', '').strip()

    if not all([amount, payment_method, transaction_id, subscription_type]):
        flash('All payment fields are required', 'error')
        return redirect(url_for('premium'))

    # Check for duplicate transaction ID
    existing_payment = Payment.query.filter_by(transaction_id=transaction_id).first()
    if existing_payment:
        flash('Transaction ID already exists', 'error')
        return redirect(url_for('premium'))

    payment = Payment(
        user_id=user.id,
        amount=amount,
        payment_method=payment_method,
        transaction_id=transaction_id,
        subscription_type=subscription_type
    )

    db.session.add(payment)
    db.session.commit()

    flash('Payment submitted for verification. You will be notified once verified.', 'info')
    log_action(user.id, 'payment_submitted', f'Payment submitted: {transaction_id} for {subscription_type}')

    return redirect(url_for('premium'))

@app.route('/messages')
@login_required
def messages():
    user = get_current_user()

    # Get user's messages
    received_messages = Message.query.filter_by(recipient_id=user.id)\
        .order_by(Message.created_at.desc()).all()

    sent_messages = Message.query.filter_by(sender_id=user.id)\
        .order_by(Message.created_at.desc()).all()

    # Mark messages as read
    for msg in received_messages:
        if not msg.is_read:
            msg.mark_as_read()

    db.session.commit()

    return render_template('messages.html', 
                         user=user, 
                         received_messages=received_messages,
                         sent_messages=sent_messages)

@app.route('/send-message', methods=['POST'])
@login_required
def send_message():
    user = get_current_user()

    subject = request.form.get('subject', '').strip()
    content = request.form.get('content', '').strip()

    if not subject or not content:
        flash('Subject and content are required', 'error')
        return redirect(url_for('messages'))

    # Send message to admin
    admin_user = User.query.filter_by(is_admin=True).first()
    if not admin_user:
        flash('No admin available to receive messages', 'error')
        return redirect(url_for('messages'))

    message = Message(
        sender_id=user.id,
        recipient_id=admin_user.id,
        subject=subject,
        content=content
    )

    db.session.add(message)
    db.session.commit()

    flash('Message sent to admin successfully', 'success')
    log_action(user.id, 'message_sent', f'Message sent to admin: {subject}')

    return redirect(url_for('messages'))

@app.route('/profile')
@login_required
def profile():
    user = get_current_user()
    return render_template('profile.html', user=user)

@app.route('/regenerate-api-key', methods=['POST'])
@login_required
def regenerate_api_key():
    user = get_current_user()
    user.generate_api_key()
    db.session.commit()

    flash('API key regenerated successfully', 'success')
    log_action(user.id, 'api_key_regenerated', 'User regenerated API key')

    return redirect(url_for('profile'))

# Admin Routes
@app.route('/admin')
@admin_required
def admin_panel():
    user = get_current_user()

    # Get system statistics
    stats = {
        'total_users': User.query.count(),
        'active_users': User.query.filter_by(is_active=True).count(),
        'premium_users': User.query.filter_by(is_premium=True).count(),
        'total_requests': OTPRequest.query.count(),
        'successful_requests': OTPRequest.query.filter_by(status='success').count(),
        'pending_payments': Payment.query.filter_by(status='pending').count(),
        'unread_messages': Message.query.filter_by(is_read=False, is_admin_message=False).count()
    }

    # Get recent activity
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    recent_requests = OTPRequest.query.order_by(OTPRequest.created_at.desc()).limit(10).all()
    pending_payments = Payment.query.filter_by(status='pending').order_by(Payment.created_at.desc()).all()

    return render_template('admin.html', 
                         user=user, 
                         stats=stats,
                         recent_users=recent_users,
                         recent_requests=recent_requests,
                         pending_payments=pending_payments)

@app.route('/admin/verify-payment/<payment_id>', methods=['POST'])
@admin_required
def verify_payment(payment_id):
    user = get_current_user()
    payment = Payment.query.get_or_404(payment_id)

    action = request.form.get('action')
    admin_notes = request.form.get('admin_notes', '').strip()

    if action == 'approve':
        payment.status = 'verified'
        payment.verified_at = datetime.utcnow()
        payment.verified_by = user.id
        payment.admin_notes = admin_notes

        # Activate premium subscription
        payment_user = User.query.get(payment.user_id)
        payment_user.is_premium = True

        if payment.subscription_type == 'premium_monthly':
            payment_user.subscription_expiry = datetime.utcnow() + timedelta(days=30)
        elif payment.subscription_type == 'premium_yearly':
            payment_user.subscription_expiry = datetime.utcnow() + timedelta(days=365)

        # Add balance
        payment_user.balance += payment.amount

        flash('Payment verified and premium activated', 'success')
        log_action(user.id, 'payment_verified', f'Payment {payment_id} verified for user {payment_user.username}')

    elif action == 'reject':
        payment.status = 'failed'
        payment.verified_by = user.id
        payment.admin_notes = admin_notes

        flash('Payment rejected', 'info')
        log_action(user.id, 'payment_rejected', f'Payment {payment_id} rejected')

    db.session.commit()
    return redirect(url_for('admin_panel'))

# API Endpoints
@app.route('/api/otp/request', methods=['POST'])
def api_request_otp():
    api_key = request.headers.get('X-API-Key') or request.form.get('api_key')

    if not api_key:
        return generate_api_response(False, 'API key required', status_code=401)

    user = User.query.filter_by(api_key=api_key, is_active=True).first()
    if not user:
        return generate_api_response(False, 'Invalid API key', status_code=401)

    phone_number = request.form.get('phone_number', '').strip()
    provider_name = request.form.get('provider', '').strip()

    if not phone_number or not provider_name:
        return generate_api_response(False, 'Phone number and provider are required')

    # Rate limiting
    if not rate_limit_check(user.id, 'api_otp_request', limit=20):
        return generate_api_response(False, 'Rate limit exceeded', status_code=429)

    provider = OTPProvider.query.filter_by(name=provider_name, is_active=True).first()
    if not provider:
        return generate_api_response(False, 'Invalid or inactive provider')

    if provider.is_premium_only and not user.is_subscription_active():
        return generate_api_response(False, 'Premium subscription required')

    if user.balance < provider.cost_per_request:
        return generate_api_response(False, 'Insufficient balance')

    # Create and process request
    otp_request = OTPRequest(
        user_id=user.id,
        provider_id=provider.id,
        phone_number=phone_number,
        ip_address=request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR')),
        user_agent=request.headers.get('User-Agent', '')
    )

    db.session.add(otp_request)
    db.session.commit()

    otp_manager = OTPProviderManager()
    try:
        result = otp_manager.request_otp(provider.name, phone_number)

        if result['success']:
            otp_request.status = 'success'
            otp_request.otp_code = result.get('otp_code')
            otp_request.cost = provider.cost_per_request
            otp_request.completed_at = datetime.utcnow()

            user.balance -= provider.cost_per_request
            provider.total_requests += 1
            provider.successful_requests += 1
            provider.update_success_rate()

            log_action(user.id, 'api_otp_success', f'API OTP success for {phone_number}')

            db.session.commit()
            return generate_api_response(True, 'OTP requested successfully', {
                'request_id': otp_request.id,
                'otp_code': result.get('otp_code'),
                'phone_number': phone_number,
                'provider': provider.name,
                'cost': provider.cost_per_request,
                'remaining_balance': user.balance
            })
        else:
            otp_request.status = 'failed'
            otp_request.error_message = result.get('error')
            otp_request.completed_at = datetime.utcnow()

            provider.total_requests += 1
            provider.update_success_rate()

            log_action(user.id, 'api_otp_failed', f'API OTP failed for {phone_number}', 'warning')

            db.session.commit()
            return generate_api_response(False, result.get('error', 'OTP request failed'))

    except Exception as e:
        otp_request.status = 'failed'
        otp_request.error_message = str(e)
        otp_request.completed_at = datetime.utcnow()

        provider.total_requests += 1
        provider.update_success_rate()

        log_action(user.id, 'api_otp_error', f'API OTP error: {str(e)}', 'error')

        db.session.commit()
        return generate_api_response(False, 'System error occurred', status_code=500)

@app.route('/api/user/balance')
def api_user_balance():
    api_key = request.headers.get('X-API-Key') or request.args.get('api_key')

    if not api_key:
        return generate_api_response(False, 'API key required', status_code=401)

    user = User.query.filter_by(api_key=api_key, is_active=True).first()
    if not user:
        return generate_api_response(False, 'Invalid API key', status_code=401)

    return generate_api_response(True, 'Balance retrieved successfully', {
        'balance': user.balance,
        'is_premium': user.is_premium,
        'subscription_active': user.is_subscription_active(),
        'subscription_expiry': user.subscription_expiry.isoformat() if user.subscription_expiry else None
    })

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# Admin Routes for Facebook Configuration
@app.route('/admin/facebook-config')
@admin_required
def admin_facebook_config():
    """Halaman konfigurasi Facebook untuk admin"""
    config = FacebookConfig.get_config()
    return render_template('admin/facebook_config.html', config=config)

# Ensure all admin routes exist
@app.route('/admin/user-management')
@admin_required
def admin_user_management():
    """Halaman management user untuk admin"""
    users = User.query.order_by(User.created_at.desc()).all()
    
    # Calculate stats
    total_users = len(users)
    premium_users = len([u for u in users if u.is_premium])
    
    return render_template('admin/user_management.html', 
                         users=users,
                         total_users=total_users,
                         premium_users=premium_users)

@app.route('/admin/add-user', methods=['POST'])
@admin_required
def admin_add_user():
    """Add new user from admin panel"""
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    is_premium = 'is_premium' in request.form
    is_admin = 'is_admin' in request.form
    
    if not username or not email or not password:
        flash('Username, email, dan password harus diisi', 'error')
        return redirect(url_for('admin_user_management'))
    
    # Check if user already exists
    if User.query.filter_by(username=username).first():
        flash('Username sudah digunakan', 'error')
        return redirect(url_for('admin_user_management'))
    
    if User.query.filter_by(email=email).first():
        flash('Email sudah digunakan', 'error')
        return redirect(url_for('admin_user_management'))
    
    try:
        # Create new user
        user = User(
            username=username,
            email=email,
            is_premium=is_premium,
            is_admin=is_admin,
            is_active=True
        )
        user.set_password(password)
        user.generate_api_key()
        
        if is_premium:
            user.subscription_expiry = datetime.utcnow() + timedelta(days=365)
        
        db.session.add(user)
        db.session.commit()
        
        flash(f'User {username} berhasil ditambahkan', 'success')
        log_action(get_current_user().id, 'admin_add_user', f'Added new user: {username}')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Gagal menambahkan user: {str(e)}', 'error')
        log_action(get_current_user().id, 'admin_add_user_error', f'Failed to add user: {str(e)}', 'error')
    
    return redirect(url_for('admin_user_management'))

@app.route('/admin/payment-management')
@admin_required
def admin_payment_management():
    """Halaman management payment untuk admin"""
    payments = Payment.query.order_by(Payment.created_at.desc()).all()
    
    # Calculate statistics for the template
    total_revenue = sum(payment.amount for payment in payments if payment.status == 'verified')
    
    # Revenue this month
    from datetime import datetime
    current_month = datetime.utcnow().month
    current_year = datetime.utcnow().year
    monthly_payments = [p for p in payments if p.created_at.month == current_month and p.created_at.year == current_year and p.status == 'verified']
    total_revenue_month = sum(payment.amount for payment in monthly_payments)
    
    # Pending payments count
    pending_count = len([p for p in payments if p.status == 'pending'])
    
    # Verified payments count
    verified_count = len([p for p in payments if p.status == 'verified'])
    
    return render_template('admin/payment_management.html', 
                         payments=payments,
                         total_revenue=total_revenue,
                         total_revenue_month=total_revenue_month,
                         pending_count=pending_count,
                         verified_count=verified_count)

@app.route('/admin/facebook-config', methods=['POST'])
@admin_required
def admin_facebook_config_post():
    """Update konfigurasi Facebook"""
    config = FacebookConfig.get_config()

    app_id = request.form.get('app_id', '').strip()
    app_secret = request.form.get('app_secret', '').strip()
    is_enabled = 'is_enabled' in request.form

    if not app_id or not app_secret:
        flash('App ID dan App Secret harus diisi', 'error')
        return redirect(url_for('admin_facebook_config'))

    try:
        config.update_config(app_id, app_secret, is_enabled)

        # Update environment variables for Facebook auth
        import os
        os.environ['FACEBOOK_OAUTH_CLIENT_ID'] = app_id
        os.environ['FACEBOOK_OAUTH_CLIENT_SECRET'] = app_secret

        flash('Konfigurasi Facebook berhasil diperbarui!', 'success')
        log_action(get_current_user().id, 'facebook_config_update', f'Updated Facebook config - Enabled: {is_enabled}')

    except Exception as e:
        flash(f'Terjadi kesalahan: {str(e)}', 'error')
        log_action(get_current_user().id, 'facebook_config_error', f'Facebook config update failed: {str(e)}', 'error')

    return redirect(url_for('admin_facebook_config'))

@app.route('/admin/test-facebook-config', methods=['POST'])
@admin_required
def test_facebook_config():
    """Test koneksi Facebook API"""
    data = request.get_json()
    app_id = data.get('app_id')
    app_secret = data.get('app_secret')

    if not app_id or not app_secret:
        return jsonify({'success': False, 'message': 'App ID dan App Secret diperlukan'})

    try:
        # Validate app_id format and app_secret length
        if not app_id.isdigit() or len(app_secret) < 20:
            return jsonify({'success': False, 'message': 'Format App ID atau App Secret tidak valid'})

        # Test Facebook API connectivity
        import requests
        test_url = f"https://graph.facebook.com/v18.0/{app_id}"
        test_params = {'access_token': f"{app_id}|{app_secret}"}

        response = requests.get(test_url, params=test_params, timeout=10)

        if response.status_code == 200:
            return jsonify({'success': True, 'message': 'Facebook API connection successful'})
        else:
            return jsonify({'success': False, 'message': f'Facebook API error: {response.status_code}'})

    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/admin/notifications')
@admin_required
def admin_notifications():
    """Halaman management notifikasi admin"""
    from models import Notification

    notifications = Notification.query.order_by(Notification.created_at.desc()).limit(100).all()
    users = User.query.filter_by(is_active=True).all()

    return render_template('admin/notifications.html', 
                         notifications=notifications, 
                         users=users)

@app.route('/admin/send-notification', methods=['POST'])
@admin_required
def admin_send_notification():
    """Send notification dari admin"""
    from models import Notification, UserSettings

    title = request.form.get('title', '').strip()
    message = request.form.get('message', '').strip()
    notification_type = request.form.get('type', 'info')
    recipient_type = request.form.get('recipient_type', 'all')
    user_id = request.form.get('user_id', '').strip()
    icon = request.form.get('icon', 'fa-bell')

    if not title or not message:
        flash('Title dan message harus diisi', 'error')
        return redirect(url_for('admin_notifications'))

    try:
        if recipient_type == 'all':
            # Send to all active users
            users = User.query.filter_by(is_active=True).all()
            for user in users:
                # Check user notification settings
                settings = UserSettings.query.filter_by(user_id=user.id).first()
                if not settings:
                    settings = UserSettings(user_id=user.id)
                    db.session.add(settings)

                if settings.push_notifications:
                    notification = Notification(
                        user_id=user.id,
                        title=title,
                        message=message,
                        type=notification_type,
                        icon=icon,
                        is_global=True
                    )
                    db.session.add(notification)

        elif recipient_type == 'specific' and user_id:
            user = User.query.get(user_id)
            if user:
                notification = Notification(
                    user_id=user.id,
                    title=title,
                    message=message,
                    type=notification_type,
                    icon=icon
                )
                db.session.add(notification)

        db.session.commit()
        flash('Notifikasi berhasil dikirim!', 'success')
        log_action(get_current_user().id, 'notification_sent', f'Sent notification: {title} to {recipient_type}')

    except Exception as e:
        db.session.rollback()
        flash(f'Gagal mengirim notifikasi: {str(e)}', 'error')
        log_action(get_current_user().id, 'notification_error', f'Failed to send notification: {str(e)}', 'error')

    return redirect(url_for('admin_notifications'))

@app.route('/admin/saldo-management')
@admin_required
def admin_saldo_management():
    """Halaman management saldo admin"""
    from models import SaldoTransaction

    users = User.query.filter_by(is_active=True).order_by(User.username).all()
    recent_transactions = SaldoTransaction.query.order_by(SaldoTransaction.created_at.desc()).limit(50).all()

    return render_template('admin/saldo_management.html', 
                         users=users, 
                         recent_transactions=recent_transactions)

@app.route('/admin/send-saldo', methods=['POST'])
@admin_required
def admin_send_saldo():
    """Transfer saldo ke user"""
    from models import SaldoTransaction, Notification

    user_id = request.form.get('user_id', '').strip()
    amount = request.form.get('amount', type=float)
    description = request.form.get('description', '').strip()

    if not user_id or not amount or amount <= 0:
        flash('User dan amount harus diisi dengan benar', 'error')
        return redirect(url_for('admin_saldo_management'))

    user = User.query.get(user_id)
    if not user:
        flash('User tidak ditemukan', 'error')
        return redirect(url_for('admin_saldo_management'))

    try:
        # Record transaction
        balance_before = user.balance
        user.balance += amount
        balance_after = user.balance

        transaction = SaldoTransaction(
            user_id=user.id,
            transaction_type='admin_transfer',
            amount=amount,
            balance_before=balance_before,
            balance_after=balance_after,
            description=description or f'Transfer dari admin',
            admin_id=get_current_user().id
        )
        db.session.add(transaction)

        # Send notification to user
        notification = Notification(
            user_id=user.id,
            title='💰 Saldo Diterima!',
            message=f'Anda telah menerima saldo sebesar Rp {amount:,.0f}. {description}',
            type='success',
            icon='fa-coins'
        )
        db.session.add(notification)

        db.session.commit()

        flash(f'Berhasil mengirim Rp {amount:,.0f} ke {user.username}', 'success')
        log_action(get_current_user().id, 'saldo_transfer', f'Transferred Rp {amount:,.0f} to {user.username}')

    except Exception as e:
        db.session.rollback()
        flash(f'Gagal mengirim saldo: {str(e)}', 'error')
        log_action(get_current_user().id, 'saldo_transfer_error', f'Failed to transfer saldo: {str(e)}', 'error')

    return redirect(url_for('admin_saldo_management'))

@app.route('/claim-daily-saldo', methods=['POST'])
@login_required
def claim_daily_saldo():
    """Claim saldo harian user"""
    from models import DailyClaim, SaldoTransaction, Notification

    user = get_current_user()
    today = datetime.utcnow().date()

    # Check if already claimed today
    existing_claim = DailyClaim.query.filter_by(
        user_id=user.id,
        claim_date=today
    ).first()

    if existing_claim:
        return jsonify({
            'success': False,
            'message': 'Anda sudah claim saldo hari ini! Silakan kembali besok.'
        })

    try:
        # Create claim record
        claim = DailyClaim(
            user_id=user.id,
            claim_date=today,
            amount=5000.0,
            ip_address=request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR')),
            user_agent=request.headers.get('User-Agent', '')
        )
        db.session.add(claim)

        # Update user balance
        balance_before = user.balance
        user.balance += 5000.0
        balance_after = user.balance

        # Record transaction
        transaction = SaldoTransaction(
            user_id=user.id,
            transaction_type='claim',
            amount=5000.0,
            balance_before=balance_before,
            balance_after=balance_after,
            description='Claim saldo harian gratis'
        )
        db.session.add(transaction)

        # Send notification
        notification = Notification(
            user_id=user.id,
            title='🎉 Claim Berhasil!',
            message='Anda telah berhasil claim saldo harian sebesar Rp 5.000! Kembali lagi besok untuk claim berikutnya.',
            type='success',
            icon='fa-gift'
        )
        db.session.add(notification)

        db.session.commit()

        log_action(user.id, 'daily_claim', 'Successfully claimed daily saldo')

        return jsonify({
            'success': True,
            'message': 'Berhasil claim Rp 5.000!',
            'new_balance': user.balance
        })

    except Exception as e:
        db.session.rollback()
        log_action(user.id, 'daily_claim_error', f'Failed to claim daily saldo: {str(e)}', 'error')

        return jsonify({
            'success': False,
            'message': f'Gagal claim saldo: {str(e)}'
        })

@app.route('/notifications')
@login_required
def user_notifications():
    """Halaman notifikasi user"""
    from models import Notification

    user = get_current_user()
    notifications = Notification.query.filter_by(user_id=user.id)\
        .order_by(Notification.created_at.desc()).all()

    return render_template('notifications.html', notifications=notifications)

@app.route('/api/notifications')
@login_required
def api_get_notifications():
    """API untuk mendapatkan notifikasi user"""
    from models import Notification

    user = get_current_user()
    notifications = Notification.query.filter_by(user_id=user.id, is_read=False)\
        .order_by(Notification.created_at.desc()).limit(10).all()

    return jsonify({
        'success': True,
        'notifications': [{
            'id': n.id,
            'title': n.title,
            'message': n.message,
            'type': n.type,
            'icon': n.icon,
            'created_at': n.created_at.isoformat(),
            'is_read': n.is_read
        } for n in notifications],
        'unread_count': len(notifications)
    })

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def api_mark_notification_read(notification_id):
    """Mark notification as read"""
    from models import Notification

    user = get_current_user()
    notification = Notification.query.filter_by(id=notification_id, user_id=user.id).first()

    if not notification:
        return jsonify({'success': False, 'message': 'Notification not found'})

    notification.mark_as_read()
    db.session.commit()

    return jsonify({'success': True, 'message': 'Notification marked as read'})

@app.route('/user/settings')
@login_required
def user_settings():
    """Halaman pengaturan user"""
    from models import UserSettings

    user = get_current_user()
    settings = UserSettings.query.filter_by(user_id=user.id).first()

    if not settings:
        settings = UserSettings(user_id=user.id)
        db.session.add(settings)
        db.session.commit()

    return render_template('user/settings.html', settings=settings)

@app.route('/user/settings', methods=['POST'])
@login_required
def update_user_settings():
    """Update pengaturan user"""
    from models import UserSettings

    user = get_current_user()
    settings = UserSettings.query.filter_by(user_id=user.id).first()

    if not settings:
        settings = UserSettings(user_id=user.id)
        db.session.add(settings)

    settings.email_notifications = 'email_notifications' in request.form
    settings.push_notifications = 'push_notifications' in request.form
    settings.marketing_notifications = 'marketing_notifications' in request.form
    settings.maintenance_notifications = 'maintenance_notifications' in request.form
    settings.payment_notifications = 'payment_notifications' in request.form

    db.session.commit()

    flash('Pengaturan berhasil disimpan!', 'success')
    return redirect(url_for('user_settings'))

@app.route('/user/my-notifications')
@login_required
def user_my_notifications():
    """User notifications page - renamed to avoid conflict"""
    from models import Notification
    user = get_current_user()
    notifications = Notification.query.filter_by(user_id=user.id)\
        .order_by(Notification.created_at.desc()).all()

    return render_template('notifications.html', notifications=notifications)

@app.route('/notifications')
@login_required
def notifications():
    """Halaman notifikasi user"""
    from models import Notification

    user = get_current_user()
    notifications = Notification.query.filter_by(user_id=user.id)\
        .order_by(Notification.created_at.desc()).all()

    return render_template('notifications.html', notifications=notifications)

@app.route('/admin/maintenance-mode', methods=['POST'])
@admin_required
def toggle_maintenance_mode():
    """Toggle maintenance mode"""
    from models import SystemSettings

    current_mode = SystemSettings.get_value('maintenance_mode', 'false')
    new_mode = 'true' if current_mode == 'false' else 'false'

    SystemSettings.set_value('maintenance_mode', new_mode, 'System maintenance mode status')

    mode_text = 'diaktifkan' if new_mode == 'true' else 'dinonaktifkan'
    flash(f'Mode maintenance berhasil {mode_text}!', 'success')

    log_action(get_current_user().id, 'maintenance_mode_toggle', f'Maintenance mode {mode_text}')

    return redirect(url_for('admin_panel'))

@app.before_request
def check_maintenance_mode():
    """Check if system is in maintenance mode"""
    from models import SystemSettings

    # Skip maintenance check for admin and auth routes
    if request.endpoint in ['login', 'logout', 'admin_panel', 'toggle_maintenance_mode', 'static']:
        return

    # Skip for admin users
    user = get_current_user()
    if user and user.is_admin:
        return

    # Check maintenance mode
    maintenance_mode = SystemSettings.get_value('maintenance_mode', 'false')
    if maintenance_mode == 'true':
        return render_template('maintenance.html'), 503

@app.route('/admin/install-packages')
@admin_required
def admin_install_packages():
    """Admin page for package installation"""
    return render_template('admin/install_packages.html')

@app.route('/admin/run-bahan', methods=['POST'])
@admin_required
def admin_run_bahan():
    """Run bahan.py installation from admin panel"""
    try:
        import subprocess
        result = subprocess.run(['python', 'bahan.py'], capture_output=True, text=True, timeout=600)
        
        if result.returncode == 0:
            flash('Package installation completed successfully!', 'success')
        else:
            flash(f'Package installation failed: {result.stderr}', 'error')
            
        log_action(get_current_user().id, 'package_install', f'Admin ran package installation')
        
    except Exception as e:
        flash(f'Failed to run package installation: {str(e)}', 'error')
        log_action(get_current_user().id, 'package_install_error', f'Package install error: {str(e)}', 'error')
    
    return redirect(url_for('admin_panel'))

@app.route('/admin/sync-facebook-settings', methods=['POST'])
@admin_required
def sync_facebook_settings():
    """Sync Facebook settings with current domain"""
    try:
        config = FacebookConfig.get_config()

        if not config.app_id or not config.app_secret:
            return jsonify({'success': False, 'message': 'Facebook credentials not configured'})

        # Get current domain info
        current_domain = request.host
        callback_url = request.url_root.rstrip('/') + '/auth/facebook_callback'

        # Ensure https for replit domains
        if 'replit' in current_domain or 'repl.co' in current_domain:
            callback_url = callback_url.replace('http://', 'https://')

        # Log sync action
        log_action(get_current_user().id, 'facebook_sync', f'Synced Facebook settings for domain: {current_domain}')

        return jsonify({
            'success': True, 
            'message': 'Settings synced successfully',
            'data': {
                'domain': current_domain,
                'callback_url': callback_url,
                'privacy_url': f"{request.url_root}privacy",
                'terms_url': f"{request.url_root}disclaimer",
                'data_deletion_url': f"{request.url_root}data-deletion"
            }
        })

    except Exception as e:
        log_action(get_current_user().id, 'facebook_sync_error', f'Facebook sync error: {str(e)}', 'error')
        return jsonify({'success': False, 'message': f'Sync failed: {str(e)}'})

@app.route('/admin/user-login-status')
@admin_required
def admin_user_login_status():
    """Halaman status login user untuk admin"""
    users = User.query.order_by(User.last_login.desc()).all()

    # Group users by login method
    password_users = [u for u in users if u.login_method == 'password']
    facebook_users = [u for u in users if u.login_method == 'facebook']

    # Statistics
    stats = {
        'total_users': len(users),
        'password_users': len(password_users),
        'facebook_users': len(facebook_users),
        'active_users': len([u for u in users if u.is_active]),
        'premium_users': len([u for u in users if u.is_premium])
    }

    return render_template('admin/user_login_status.html', 
                         users=users,
                         password_users=password_users,
                         facebook_users=facebook_users,
                         stats=stats)

@app.route('/admin/api-key-management')
@admin_required
def admin_api_key_management():
    """Halaman management API key untuk admin"""
    users = User.query.filter_by(is_active=True).order_by(User.username).all()
    return render_template('admin/api_key_management.html', users=users)

@app.route('/admin/generate-api-key', methods=['POST'])
@admin_required
def admin_generate_api_key():
    """Generate API key untuk user dengan fitur lengkap"""
    user_id = request.form.get('user_id', '').strip()
    expiry_days = request.form.get('expiry_days')
    custom_expiry = request.form.get('custom_expiry', type=int)
    initial_status = request.form.get('initial_status', 'enabled')
    set_premium = request.form.get('set_premium', '').strip()
    admin_notes = request.form.get('admin_notes', '').strip()
    
    if not user_id:
        flash('User harus dipilih', 'error')
        return redirect(url_for('admin_api_key_management'))
    
    user = User.query.get(user_id)
    if not user:
        flash('User tidak ditemukan', 'error')
        return redirect(url_for('admin_api_key_management'))
    
    try:
        # Generate new API key
        old_api_key = user.api_key
        user.generate_api_key()
        
        # Set expiry
        if expiry_days == 'custom' and custom_expiry and custom_expiry > 0:
            user.api_key_expiry = datetime.utcnow() + timedelta(days=custom_expiry)
        elif expiry_days and expiry_days.isdigit():
            days = int(expiry_days)
            if days > 0:
                user.api_key_expiry = datetime.utcnow() + timedelta(days=days)
            else:
                user.api_key_expiry = None
        else:
            user.api_key_expiry = None
        
        # Set initial status
        user.api_key_enabled = (initial_status == 'enabled')
        
        # Handle premium setting
        if set_premium == 'enable':
            user.is_premium = True
            if not user.subscription_expiry or user.subscription_expiry < datetime.utcnow():
                user.subscription_expiry = datetime.utcnow() + timedelta(days=365)
        elif set_premium == 'disable':
            user.is_premium = False
            user.subscription_expiry = None
        
        db.session.commit()
        
        # Create detailed log
        log_details = f'Generated API key for {user.username}'
        if old_api_key:
            log_details += ' (replaced existing key)'
        if expiry_days:
            log_details += f', Expiry: {expiry_days} days'
        if set_premium:
            log_details += f', Premium: {set_premium}'
        if admin_notes:
            log_details += f', Notes: {admin_notes}'
        
        flash(f'API key berhasil digenerate untuk {user.username}', 'success')
        log_action(get_current_user().id, 'admin_generate_api_key', log_details)
        
        # Send notification to user
        try:
            from models import Notification
            notification = Notification(
                user_id=user.id,
                title='🔑 API Key Generated',
                message=f'Admin telah generate API key baru untuk akun Anda. Status: {"Aktif" if user.api_key_enabled else "Nonaktif"}',
                type='info',
                icon='fa-key'
            )
            db.session.add(notification)
            db.session.commit()
        except:
            pass  # Don't fail if notification fails
        
    except Exception as e:
        db.session.rollback()
        flash(f'Gagal generate API key: {str(e)}', 'error')
        log_action(get_current_user().id, 'admin_generate_api_key_error', f'Failed to generate API key: {str(e)}', 'error')
    
    return redirect(url_for('admin_api_key_management'))

@app.route('/admin/toggle-api-key-status', methods=['POST'])
@admin_required  
def admin_toggle_api_key_status():
    """Toggle status API key user"""
    user_id = request.form.get('user_id', '').strip()
    action = request.form.get('action', '').strip()
    
    if not user_id or action not in ['enable', 'disable']:
        flash('Parameter tidak valid', 'error')
        return redirect(url_for('admin_api_key_management'))
    
    user = User.query.get(user_id)
    if not user:
        flash('User tidak ditemukan', 'error')
        return redirect(url_for('admin_api_key_management'))
    
    try:
        if action == 'enable':
            user.api_key_enabled = True
            message = f'API key {user.username} berhasil diaktifkan'
        else:
            user.api_key_enabled = False
            message = f'API key {user.username} berhasil dinonaktifkan'
            
        db.session.commit()
        
        flash(message, 'success')
        log_action(get_current_user().id, f'admin_api_key_{action}', f'API key {action}d for {user.username}')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Gagal mengubah status API key: {str(e)}', 'error')
        log_action(get_current_user().id, 'admin_api_key_toggle_error', f'Failed to toggle API key: {str(e)}', 'error')
    
    return redirect(url_for('admin_api_key_management'))

@app.route('/admin/extend-api-key', methods=['POST'])
@admin_required
def admin_extend_api_key():
    """Extend API key expiry"""
    user_id = request.form.get('user_id', '').strip()
    extend_days = request.form.get('extend_days', type=int)
    
    if not user_id or not extend_days or extend_days <= 0:
        flash('Parameter tidak valid', 'error')
        return redirect(url_for('admin_api_key_management'))
    
    user = User.query.get(user_id)
    if not user:
        flash('User tidak ditemukan', 'error')
        return redirect(url_for('admin_api_key_management'))
    
    try:
        if user.api_key_expiry:
            user.api_key_expiry = user.api_key_expiry + timedelta(days=extend_days)
        else:
            user.api_key_expiry = datetime.utcnow() + timedelta(days=extend_days)
            
        db.session.commit()
        
        flash(f'API key {user.username} berhasil diperpanjang {extend_days} hari', 'success')
        log_action(get_current_user().id, 'admin_extend_api_key', f'Extended API key for {user.username} by {extend_days} days')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Gagal memperpanjang API key: {str(e)}', 'error')
        log_action(get_current_user().id, 'admin_extend_api_key_error', f'Failed to extend API key: {str(e)}', 'error')
    
    return redirect(url_for('admin_api_key_management'))

@app.route('/admin/delete-api-key', methods=['POST'])
@admin_required
def admin_delete_api_key():
    """Delete API key"""
    user_id = request.form.get('user_id', '').strip()
    deletion_reason = request.form.get('deletion_reason', '').strip()
    
    if not user_id or not deletion_reason:
        flash('User ID dan alasan penghapusan harus diisi', 'error')
        return redirect(url_for('admin_api_key_management'))
    
    user = User.query.get(user_id)
    if not user:
        flash('User tidak ditemukan', 'error')
        return redirect(url_for('admin_api_key_management'))
    
    try:
        old_api_key = user.api_key
        user.api_key = None
        user.api_key_enabled = False
        user.api_key_expiry = None
        
        db.session.commit()
        
        flash(f'API key untuk {user.username} berhasil dihapus', 'success')
        log_action(get_current_user().id, 'admin_delete_api_key', f'Deleted API key for {user.username}. Reason: {deletion_reason}')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Gagal menghapus API key: {str(e)}', 'error')
        log_action(get_current_user().id, 'admin_delete_api_key_error', f'Failed to delete API key: {str(e)}', 'error')
    
    return redirect(url_for('admin_api_key_management'))

@app.route('/admin/regenerate-api-key', methods=['POST'])
@admin_required
def admin_regenerate_api_key():
    """Regenerate API key"""
    user_id = request.form.get('user_id', '').strip()
    keep_expiry = 'keep_expiry' in request.form
    regeneration_reason = request.form.get('regeneration_reason', '').strip()
    
    if not user_id:
        flash('User ID harus diisi', 'error')
        return redirect(url_for('admin_api_key_management'))
    
    user = User.query.get(user_id)
    if not user:
        flash('User tidak ditemukan', 'error')
        return redirect(url_for('admin_api_key_management'))
    
    try:
        old_expiry = user.api_key_expiry if keep_expiry else None
        user.generate_api_key()
        
        if keep_expiry and old_expiry:
            user.api_key_expiry = old_expiry
        
        user.api_key_enabled = True
        db.session.commit()
        
        flash(f'API key untuk {user.username} berhasil di-regenerate', 'success')
        log_action(get_current_user().id, 'admin_regenerate_api_key', f'Regenerated API key for {user.username}. Reason: {regeneration_reason}')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Gagal regenerate API key: {str(e)}', 'error')
        log_action(get_current_user().id, 'admin_regenerate_api_key_error', f'Failed to regenerate API key: {str(e)}', 'error')
    
    return redirect(url_for('admin_api_key_management'))

@app.route('/admin/set-premium', methods=['POST'])
@admin_required
def admin_set_premium():
    """Set premium status for user"""
    user_id = request.form.get('user_id', '').strip()
    premium_action = request.form.get('premium_action', '').strip()
    premium_duration = request.form.get('premium_duration', '').strip()
    add_balance = request.form.get('add_balance', type=float)
    
    if not user_id or not premium_action:
        flash('Parameter tidak valid', 'error')
        return redirect(url_for('admin_api_key_management'))
    
    user = User.query.get(user_id)
    if not user:
        flash('User tidak ditemukan', 'error')
        return redirect(url_for('admin_api_key_management'))
    
    try:
        if premium_action == 'enable':
            user.is_premium = True
            if premium_duration == 'lifetime':
                user.subscription_expiry = None
            else:
                days = int(premium_duration)
                user.subscription_expiry = datetime.utcnow() + timedelta(days=days)
        elif premium_action == 'disable':
            user.is_premium = False
            user.subscription_expiry = None
        elif premium_action == 'extend':
            if user.subscription_expiry and user.subscription_expiry > datetime.utcnow():
                days = int(premium_duration)
                user.subscription_expiry = user.subscription_expiry + timedelta(days=days)
            else:
                days = int(premium_duration)
                user.subscription_expiry = datetime.utcnow() + timedelta(days=days)
            user.is_premium = True
        
        # Add balance if specified
        if add_balance and add_balance > 0:
            user.balance += add_balance
            
            # Create saldo transaction record
            from models import SaldoTransaction
            transaction = SaldoTransaction(
                user_id=user.id,
                transaction_type='admin_premium_bonus',
                amount=add_balance,
                balance_before=user.balance - add_balance,
                balance_after=user.balance,
                description=f'Bonus saldo dari admin saat {premium_action} premium',
                admin_id=get_current_user().id
            )
            db.session.add(transaction)
        
        db.session.commit()
        
        action_text = {
            'enable': 'diaktifkan',
            'disable': 'dinonaktifkan', 
            'extend': 'diperpanjang'
        }
        
        flash(f'Premium {user.username} berhasil {action_text[premium_action]}', 'success')
        log_action(get_current_user().id, 'admin_set_premium', f'Premium {action_text[premium_action]} for {user.username}')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Gagal mengubah status premium: {str(e)}', 'error')
        log_action(get_current_user().id, 'admin_set_premium_error', f'Failed to set premium: {str(e)}', 'error')
    
    return redirect(url_for('admin_api_key_management'))

@app.route('/admin/user-details/<user_id>')
@admin_required
def admin_user_details(user_id):
    """Get user details for modal"""
    user = User.query.get_or_404(user_id)
    
    # Get user statistics
    from models import OTPRequest, Payment, SaldoTransaction
    stats = {
        'total_requests': OTPRequest.query.filter_by(user_id=user.id).count(),
        'successful_requests': OTPRequest.query.filter_by(user_id=user.id, status='success').count(),
        'total_payments': Payment.query.filter_by(user_id=user.id).count(),
        'verified_payments': Payment.query.filter_by(user_id=user.id, status='verified').count(),
        'total_spent': db.session.query(db.func.sum(SaldoTransaction.amount)).filter_by(
            user_id=user.id, 
            transaction_type='otp_request'
        ).scalar() or 0
    }
    
    # Get recent activity
    recent_requests = OTPRequest.query.filter_by(user_id=user.id)\
        .order_by(OTPRequest.created_at.desc()).limit(5).all()
    recent_payments = Payment.query.filter_by(user_id=user.id)\
        .order_by(Payment.created_at.desc()).limit(3).all()
    
    return render_template('admin/user_details_modal.html', 
                         user=user, 
                         stats=stats,
                         recent_requests=recent_requests,
                         recent_payments=recent_payments)

@app.route('/admin/edit-user/<user_id>')
@admin_required
def admin_edit_user(user_id):
    """Edit user page"""
    user = User.query.get_or_404(user_id)
    return render_template('admin/edit_user.html', user=user)

@app.route('/admin/edit-user/<user_id>', methods=['POST'])
@admin_required
def admin_update_user(user_id):
    """Update user details"""
    user = User.query.get_or_404(user_id)
    
    try:
        # Update basic info
        user.username = request.form.get('username', '').strip()
        user.email = request.form.get('email', '').strip()
        
        # Update password if provided
        new_password = request.form.get('password', '').strip()
        if new_password:
            user.set_password(new_password)
        
        # Update status
        user.is_active = 'is_active' in request.form
        user.is_premium = 'is_premium' in request.form
        user.is_admin = 'is_admin' in request.form
        
        # Update balance
        new_balance = request.form.get('balance', type=float)
        if new_balance is not None:
            user.balance = new_balance
        
        # Update premium expiry
        if user.is_premium:
            expiry_date = request.form.get('premium_expiry')
            if expiry_date:
                from datetime import datetime
                user.subscription_expiry = datetime.strptime(expiry_date, '%Y-%m-%d')
        
        db.session.commit()
        
        flash(f'User {user.username} updated successfully', 'success')
        log_action(get_current_user().id, 'admin_edit_user', f'Updated user: {user.username}')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating user: {str(e)}', 'error')
        log_action(get_current_user().id, 'admin_edit_user_error', f'Failed to update user: {str(e)}', 'error')
    
    return redirect(url_for('admin_user_management'))

@app.route('/admin/toggle-premium/<user_id>', methods=['POST'])
@admin_required
def admin_toggle_premium(user_id):
    """Toggle user premium status"""
    user = User.query.get_or_404(user_id)
    
    try:
        user.is_premium = not user.is_premium
        
        if user.is_premium:
            # Set 1 year expiry for new premium users
            from datetime import datetime, timedelta
            user.subscription_expiry = datetime.utcnow() + timedelta(days=365)
        else:
            user.subscription_expiry = None
        
        db.session.commit()
        
        status = 'activated' if user.is_premium else 'deactivated'
        log_action(get_current_user().id, 'admin_toggle_premium', f'Premium {status} for {user.username}')
        
        return jsonify({
            'success': True, 
            'message': f'Premium {status} for {user.username}',
            'is_premium': user.is_premium
        })
        
    except Exception as e:
        db.session.rollback()
        log_action(get_current_user().id, 'admin_toggle_premium_error', f'Error toggling premium: {str(e)}', 'error')
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/toggle-status/<user_id>', methods=['POST'])
@admin_required
def admin_toggle_status(user_id):
    """Toggle user active status"""
    user = User.query.get_or_404(user_id)
    
    try:
        user.is_active = not user.is_active
        db.session.commit()
        
        status = 'activated' if user.is_active else 'deactivated'
        log_action(get_current_user().id, 'admin_toggle_status', f'User {status}: {user.username}')
        
        return jsonify({
            'success': True, 
            'message': f'User {status}: {user.username}',
            'is_active': user.is_active
        })
        
    except Exception as e:
        db.session.rollback()
        log_action(get_current_user().id, 'admin_toggle_status_error', f'Error toggling status: {str(e)}', 'error')
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/user-api-keys/<user_id>')
@admin_required
def admin_user_api_keys(user_id):
    """Get user API keys for modal"""
    user = User.query.get_or_404(user_id)
    return render_template('admin/user_api_keys_modal.html', user=user)

@app.route('/admin/bulk-api-actions', methods=['POST'])
@admin_required
def admin_bulk_api_actions():
    """Handle bulk actions for API keys"""
    user_ids = request.form.getlist('user_ids[]')
    bulk_action = request.form.get('bulk_action', '').strip()
    
    if not user_ids or not bulk_action:
        flash('Pilih minimal satu user dan action', 'error')
        return redirect(url_for('admin_api_key_management'))
    
    try:
        success_count = 0
        error_count = 0
        
        for user_id in user_ids:
            user = User.query.get(user_id)
            if not user:
                error_count += 1
                continue
                
            try:
                if bulk_action == 'enable_keys':
                    if user.api_key:
                        user.api_key_enabled = True
                        success_count += 1
                elif bulk_action == 'disable_keys':
                    if user.api_key:
                        user.api_key_enabled = False
                        success_count += 1
                elif bulk_action == 'extend_keys':
                    extend_days = request.form.get('extend_days', type=int)
                    if user.api_key and extend_days:
                        if user.api_key_expiry:
                            user.api_key_expiry = user.api_key_expiry + timedelta(days=extend_days)
                        else:
                            user.api_key_expiry = datetime.utcnow() + timedelta(days=extend_days)
                        success_count += 1
                elif bulk_action == 'delete_keys':
                    if user.api_key:
                        user.api_key = None
                        user.api_key_enabled = False
                        user.api_key_expiry = None
                        success_count += 1
                elif bulk_action == 'regenerate_keys':
                    if user.api_key:
                        user.generate_api_key()
                        user.api_key_enabled = True
                        success_count += 1
                elif bulk_action == 'set_premium':
                    user.is_premium = True
                    user.subscription_expiry = datetime.utcnow() + timedelta(days=365)
                    success_count += 1
                elif bulk_action == 'add_balance':
                    balance_amount = request.form.get('balance_amount', type=float)
                    if balance_amount and balance_amount > 0:
                        user.balance += balance_amount
                        success_count += 1
                        
            except Exception as e:
                error_count += 1
                continue
        
        db.session.commit()
        
        if success_count > 0:
            flash(f'Bulk action berhasil untuk {success_count} user(s)', 'success')
        if error_count > 0:
            flash(f'Gagal untuk {error_count} user(s)', 'warning')
            
        log_action(get_current_user().id, 'admin_bulk_api_actions', f'Bulk action {bulk_action} - Success: {success_count}, Error: {error_count}')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Gagal melakukan bulk action: {str(e)}', 'error')
        log_action(get_current_user().id, 'admin_bulk_api_actions_error', f'Bulk action failed: {str(e)}', 'error')
    
    return redirect(url_for('admin_api_key_management'))