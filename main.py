
import os
import sys
from flask import Flask

def create_app():
    """Create and configure Flask app"""
    try:
        # Import app and db
        from app import app, db
        
        with app.app_context():
            try:
                # Import all models
                print("🔄 Importing models...")
                import models
                import routes
                
                # Check if database exists and is valid
                print("🔍 Checking database...")
                
                # Try to query a user to test database
                try:
                    from models import User
                    test_query = User.query.first()
                    print("✅ Database is valid and accessible")
                except Exception as db_error:
                    print(f"❌ Database error detected: {db_error}")
                    print("🔧 Running database fix...")
                    
                    # Run database fix
                    import subprocess
                    result = subprocess.run([sys.executable, 'fix_database.py'], 
                                          capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        print("✅ Database fixed successfully")
                    else:
                        print(f"❌ Database fix failed: {result.stderr}")
                        return None
                
                # Ensure admin user exists
                print("🔍 Checking admin user...")
                from models import User
                from werkzeug.security import generate_password_hash
                
                admin_user = User.query.filter_by(username='DeltaProject').first()
                if not admin_user:
                    print("🔄 Creating admin user...")
                    admin_user = User(
                        username='DeltaProject',
                        email='admin@deltaproject.com',
                        password_hash=generate_password_hash('Admin'),
                        is_admin=True,
                        is_active=True,
                        login_method='password',
                        api_key_enabled=True,
                        balance=1000000.0
                    )
                    admin_user.generate_api_key()
                    db.session.add(admin_user)
                    db.session.commit()
                    print("✅ Admin user created successfully")
                else:
                    print("✅ Admin user already exists")
                
                print("✅ Application initialized successfully")
                print("🚀 DeltaPro Control Panel is ready!")
                print(f"📊 Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
                
                return app
                
            except Exception as init_error:
                print(f"❌ Initialization error: {init_error}")
                import traceback
                traceback.print_exc()
                
                # Try to fix database one more time
                print("🔧 Attempting emergency database fix...")
                try:
                    import subprocess
                    result = subprocess.run([sys.executable, 'fix_database.py'], 
                                          capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        print("✅ Emergency fix successful, restarting...")
                        # Import again after fix
                        import importlib
                        importlib.reload(models)
                        importlib.reload(routes)
                        return app
                    else:
                        print(f"❌ Emergency fix failed: {result.stderr}")
                        return None
                        
                except Exception as fix_error:
                    print(f"❌ Emergency fix error: {fix_error}")
                    return None
                    
    except Exception as e:
        print(f"❌ Fatal error creating app: {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    """Main function to run the application"""
    print("🚀 Starting DeltaPro Control Panel...")
    print("=" * 50)
    
    app = create_app()
    if app is None:
        print("💥 Failed to create application")
        print("🔧 Please run: python fix_database.py")
        sys.exit(1)
    
    try:
        print("🌐 Starting Flask server...")
        print("📍 Server will be available at: http://0.0.0.0:5000")
        print("🔑 Admin login: Username=DeltaProject, Password=Admin")
        print("=" * 50)
        
        app.run(host="0.0.0.0", port=5000, debug=True)
        
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
