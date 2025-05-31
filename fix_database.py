
#!/usr/bin/env python3

import os
import sys
import sqlite3
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

def fix_database():
    """Complete database fix"""
    print("🔧 Starting complete database fix...")
    
    # Create instance directory if it doesn't exist
    instance_dir = 'instance'
    if not os.path.exists(instance_dir):
        os.makedirs(instance_dir)
        print("✅ Created instance directory")
    
    # Remove old database file if exists
    db_path = os.path.join(instance_dir, 'deltapro.db')
    if os.path.exists(db_path):
        os.remove(db_path)
        print("✅ Removed old database file")
    
    # Create Flask app for database operations
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db = SQLAlchemy(app)
    
    with app.app_context():
        try:
            # Import models to register them with SQLAlchemy
            print("🔄 Importing models...")
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            
            # Import all models
            from models import (
                User, OTPProvider, OTPRequest, Message, Payment, 
                AuditLog, RateLimit, SystemSettings, FacebookConfig,
                UserApiKey, CustomOTPService, SystemReport, MessageReply,
                Notification, UserSettings, DailyClaim, SaldoTransaction
            )
            
            # Create all tables with complete schema
            print("🔄 Creating all database tables...")
            db.create_all()
            print("✅ All tables created successfully")
            
            # Create default admin user
            print("🔄 Creating default admin user...")
            from werkzeug.security import generate_password_hash
            
            admin_user = User(
                username='DeltaProject',
                email='admin@deltaproject.com',
                password_hash=generate_password_hash('Admin'),
                is_admin=True,
                is_active=True,
                login_method='password',
                api_key_enabled=True,
                balance=1000000.0  # Give admin 1M balance
            )
            admin_user.generate_api_key()
            db.session.add(admin_user)
            
            # Create default user settings for admin
            admin_settings = UserSettings(
                user_id=admin_user.id,
                email_notifications=True,
                push_notifications=True,
                marketing_notifications=False,
                maintenance_notifications=True,
                payment_notifications=True
            )
            db.session.add(admin_settings)
            
            # Create default OTP providers
            print("🔄 Creating default OTP providers...")
            providers = [
                {
                    'name': 'sms_activate',
                    'display_name': 'SMS Activate',
                    'base_url': 'https://sms-activate.org/stubs/handler_api.php',
                    'cost_per_request': 1000.0,
                    'is_premium_only': False,
                    'is_active': True
                },
                {
                    'name': 'sms_man',
                    'display_name': 'SMS Man',
                    'base_url': 'http://api.sms-man.ru/control',
                    'cost_per_request': 1200.0,
                    'is_premium_only': False,
                    'is_active': True
                },
                {
                    'name': 'temp_sms',
                    'display_name': 'Temp SMS',
                    'base_url': 'https://tempsmss.com/api',
                    'cost_per_request': 800.0,
                    'is_premium_only': True,
                    'is_active': True
                }
            ]
            
            for provider_data in providers:
                provider = OTPProvider(**provider_data)
                db.session.add(provider)
            
            # Create Facebook config
            print("🔄 Creating Facebook configuration...")
            fb_config = FacebookConfig(
                app_id='',
                app_secret='',
                is_enabled=False
            )
            db.session.add(fb_config)
            
            # Create system settings
            print("🔄 Creating system settings...")
            settings = [
                ('maintenance_mode', 'false', 'Enable/disable maintenance mode'),
                ('registration_enabled', 'true', 'Enable/disable user registration'),
                ('max_otp_requests_per_day', '50', 'Maximum OTP requests per day for free users'),
                ('premium_otp_requests_per_day', '500', 'Maximum OTP requests per day for premium users'),
                ('daily_claim_amount', '5000', 'Daily claim amount in saldo'),
                ('site_title', 'DeltaPro Control Panel', 'Website title'),
                ('site_description', 'Advanced OTP and SMS Services', 'Website description')
            ]
            
            for key, value, description in settings:
                setting = SystemSettings(key=key, value=value, description=description)
                db.session.add(setting)
            
            # Commit all changes
            db.session.commit()
            
            print("✅ Database fixed successfully!")
            print("✅ Admin user created:")
            print("   - Username: DeltaProject")
            print("   - Password: Admin")
            print("   - Balance: 1,000,000")
            print("✅ Default OTP providers created")
            print("✅ System settings initialized")
            print("✅ Application ready to run!")
            
            return True
            
        except Exception as e:
            print(f"❌ Error fixing database: {e}")
            import traceback
            traceback.print_exc()
            db.session.rollback()
            return False

if __name__ == "__main__":
    if fix_database():
        print("\n🎉 Database fix completed successfully!")
        sys.exit(0)
    else:
        print("\n💥 Database fix failed!")
        sys.exit(1)
