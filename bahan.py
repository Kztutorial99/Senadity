#!/usr/bin/env python3
"""
Bahan.py - DeltaPro Package Manager
Auto-installer untuk semua dependencies yang dibutuhkan
"""

import subprocess
import sys
import os
import time

class Colors:
    """ANSI color codes untuk terminal yang colorful"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class BahanManager:
    def __init__(self):
        self.all_packages = [
            # Core Flask packages
            "Flask==2.3.3",
            "Flask-SQLAlchemy==3.0.5", 
            "Werkzeug==2.3.7",
            "Jinja2>=3.1.2",
            "itsdangerous>=2.1.2",
            "click>=8.1.3",
            "blinker>=1.6.2",
            "MarkupSafe>=2.1.1",

            # Database
            "psycopg2-binary==2.9.7",
            "sqlalchemy>=2.0.0",
            "greenlet>=1",

            # Environment & Config
            "python-dotenv==1.0.0",

            # HTTP & Requests
            "requests==2.31.0",
            "urllib3>=1.21.1",
            "certifi>=2017.4.17",
            "charset-normalizer>=2",
            "idna>=2.5",

            # Authentication & OAuth
            "email-validator>=2.2.0",
            "dnspython>=2.0.0",
            "flask-dance>=7.1.0",
            "flask-login>=0.6.3",
            "oauthlib>=3.2.2",
            "requests-oauthlib>=1.0.0",
            "urlobject",
            "pyjwt>=2.10.1",

            # Production Server
            "gunicorn>=23.0.0",
            "packaging",

            # Optional packages
            "flask-wtf>=1.1.1",
            "wtforms>=3.0.1", 
            "pillow>=10.0.0",
            "redis>=4.5.0",
            "celery>=5.3.0",
            "flask-mail>=0.9.1",
            "qrcode>=7.4.2",
            "python-barcode>=0.14.0"
        ]

    def print_header(self):
        """Print header"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.OKCYAN}🚀 Installing DeltaPro Control Panel...{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")

    def run_command(self, command, description=""):
        """Run shell command with error handling"""
        try:
            print(f"{Colors.OKCYAN}🔄 {description}...{Colors.ENDC}")

            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=300
            )

            if result.returncode == 0:
                print(f"{Colors.OKGREEN}✅ {description} berhasil!{Colors.ENDC}")
                return True
            else:
                print(f"{Colors.WARNING}⚠️ {description} ada warning tapi lanjut...{Colors.ENDC}")
                return True  # Continue even with warnings for pip installs

        except Exception as e:
            print(f"{Colors.FAIL}❌ Error: {str(e)}{Colors.ENDC}")
            return False

    def install_all_packages(self):
        """Install all packages automatically"""
        print(f"{Colors.BOLD}{Colors.OKBLUE}📦 Installing Python packages...{Colors.ENDC}")

        # Upgrade pip first
        self.run_command(
            "python -m pip install --upgrade pip setuptools wheel --no-warn-script-location", 
            "Upgrading pip and tools"
        )

        # Install from requirements.txt first
        if os.path.exists("requirements.txt"):
            self.run_command(
                "pip install -r requirements.txt --no-cache-dir --no-warn-script-location", 
                "Installing from requirements.txt"
            )

        # Install additional packages
        additional_packages = [
            "flask-wtf>=1.1.1",
            "wtforms>=3.0.1", 
            "pillow>=10.0.0",
            "qrcode>=7.4.2",
            "python-barcode>=0.14.0"
        ]

        for package in additional_packages:
            self.run_command(
                f"pip install {package} --no-cache-dir --no-warn-script-location", 
                f"Installing {package}"
            )
            time.sleep(0.2)

    def fix_database(self):
        """Fix database automatically"""
        print(f"{Colors.BOLD}{Colors.OKBLUE}🗄️ Updating database schema...{Colors.ENDC}")

        if os.path.exists("fix_database.py"):
            self.run_command("python fix_database.py", "Running database fix")

        if os.path.exists("update_schema.py"):
            self.run_command("python update_schema.py", "Updating database schema")

    def complete_installation(self):
        """Complete auto installation"""
        self.print_header()

        # Install packages
        self.install_all_packages()

        # Fix database
        self.fix_database()

        # Final message
        print(f"\n{Colors.BOLD}{Colors.OKGREEN}✅ Installation completed successfully!{Colors.ENDC}")
        print(f"\n{Colors.BOLD}{Colors.OKCYAN}🎉 DeltaPro Control Panel is ready to use!{Colors.ENDC}")
        print(f"{Colors.OKGREEN}📝 Admin credentials have been saved to admin_info.py{Colors.ENDC}")
        print(f"{Colors.OKGREEN}🔧 You can now run the application with: python main.py{Colors.ENDC}")

def main():
    """Main function - auto install everything"""
    try:
        manager = BahanManager()
        manager.complete_installation()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}⚠️ Installation dihentikan oleh user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.FAIL}❌ Fatal error: {str(e)}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()