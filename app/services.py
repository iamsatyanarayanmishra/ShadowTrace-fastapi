from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import HTTPException
from app.database import get_db
from app.models import User
from sqlalchemy.orm import Session
from fastapi import Depends
import ipaddress
import logging
import re
from typing import List, Dict, Any, Tuple

# Hashing passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Helper to hash passwords
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Helper function to create access tokens
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Function to generate OTP
def generate_otp(email: str, db: Session = Depends(get_db)):
    otp = str(random.randint(100000, 999999))
    return otp

def send_email(email: str, otp: str):
    # Email configuration
    sender_email = "iamsatyanarayanmishra@gmail.com"  # Replace with your email
    sender_password = "meil pcfa plsc sdjd"    # Use your Google account password or App Password
    subject = "Your OTP Code"
    body = f"Your OTP code is: {otp}"

    # Create the email
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to the SMTP server
        with smtplib.SMTP('smtp.gmail.com', 587) as server:  # Use Gmail's SMTP server
            server.starttls()  # Upgrade the connection to secure
            server.login(sender_email, sender_password)  # Login to your email account
            server.send_message(msg)  # Send the email

        print(f"Sending OTP {otp} to email {email}")

    except Exception as e:
        print(f"Failed to send email: {e}")
        raise HTTPException(status_code=500, detail="Email sending failed")
    
# Function to send username and password
# def send_username_password(email: str, username: str, password: str):
#     # Email configuration
#     sender_email = "iamsatyanarayanmishra@gmail.com"  # Replace with your email
#     sender_password = "meil pcfa plsc sdjd"    # Use your Google account password or App Password
#     subject = "Your OTP Code"
#     body = f"Your username and password is: {username, password}"

#     # Create the email
#     msg = MIMEMultipart()
#     msg['From'] = sender_email
#     msg['To'] = email
#     msg['Subject'] = subject
#     msg.attach(MIMEText(body, 'plain'))

#     try:
#         # Connect to the SMTP server
#         with smtplib.SMTP('smtp.gmail.com', 587) as server:  # Use Gmail's SMTP server
#             server.starttls()  # Upgrade the connection to secure
#             server.login(sender_email, sender_password)  # Login to your email account
#             server.send_message(msg)  # Send the email

#         print(f"Sending username and password {username, password} to email {email}")

#     except Exception as e:
#         print(f"Failed to send email: {e}")
#         raise HTTPException(status_code=500, detail="Email sending failed")
    

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def extract_cves_from_scripts(port_info: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    cve_list = []
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    # Extract 'vulners' string
    vulners_info = port_info.get("script", {}).get('vulners', '')
    
    # Regular expression to capture CVE and severity scores
    cve_pattern = re.compile(r'(CVE-\d{4}-\d+)\s+([\d.]+)\s+(https?://\S+)')
    
    # Find all CVEs in the vulners string
    for match in cve_pattern.finditer(vulners_info):
        cve_id = match.group(1)
        severity_score = float(match.group(2))
        cve_url = match.group(3)

        # Append CVE details to the list
        cve_data = {
            "cve_id": cve_id.upper(),
            "severity_score": severity_score,
            "description": "No description provided",  # Placeholder
            "url": cve_url
        }
        cve_list.append(cve_data)

        # Count severity
        if severity_score >= 9:
            severity_counts["Critical"] += 1
        elif severity_score >= 7:
            severity_counts["High"] += 1
        elif severity_score >= 4:
            severity_counts["Medium"] += 1
        else:
            severity_counts["Low"] += 1

    return cve_list, severity_counts

def extract_host_cves(host_scripts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    host_cves = []
    for script in host_scripts:
        script_id = script.get('id', '')
        if 'cve' in script_id.lower():
            parts = script_id.lower().split('cve-')
            if len(parts) > 1:
                cve_id = 'CVE-' + parts[1].upper()
                host_cves.append({
                    "cve_id": cve_id,
                    "severity_score": "N/A",
                    "description": "No description provided"
                })
                logger.info(f"Detected CVE from host script: {cve_id}")
    return host_cves

def format_scan_results(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    formatted_results = []
    total_cves = 0
    open_ports = []
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    mac_address = scan_data.get("addresses", {}).get("mac", "Unknown MAC")
    vendor = scan_data.get("vendor", {}).get(mac_address, "unknown vendor")
    hostnames = scan_data.get("hostnames", [])
    system_name = hostnames[0].get("name", "Unknown system name") if hostnames else "Unknown system name"

    for protocol in ['tcp', 'udp']:
        ports = scan_data.get(protocol, {})
        for port, port_info in ports.items():
            if port_info.get('state') == 'open':
                open_ports.append(int(port))

                # Extract CVEs from port information
                cve_list, counts = extract_cves_from_scripts(port_info)
                severity_counts = {k: severity_counts[k] + counts[k] for k in severity_counts}
                total_cves += len(cve_list)

                formatted_results.append({
                    "port": int(port),
                    "protocol": protocol,
                    "state": port_info.get("state", ""),
                    "service": port_info.get("name", ""),
                    "version": port_info.get("version", ""),
                    "cves": cve_list
                })

    host_scripts = scan_data.get("hostscript", [])
    host_cves = extract_host_cves(host_scripts)
    total_cves += len(host_cves)
    severity_counts["Low"] += len(host_cves)  # Assuming host CVEs are low severity

    os_matches = scan_data.get("osmatch", [])
    operating_system = os_matches[0].get("name", "Unknown OS") if os_matches else "Unknown OS"

    uptime = scan_data.get("uptime", {}).get("seconds", "Unknown")
    last_boot = scan_data.get("uptime", {}).get("lastboot", "Unknown")
    scan_duration = scan_data.get('scan_duration', 0)

    summary = { 
        "total_cves": total_cves,
        "severity_counts": severity_counts,
        "vendor": vendor,
        "operating_system": operating_system,
        "uptime_seconds": uptime,
        "last_boot": last_boot,
        "scan_duration": f"{scan_duration:.2f} seconds",
        "total_open_ports": len(open_ports),
        "open_ports": sorted(open_ports),
        "mac_address": mac_address,
        "system_name": system_name,
        "host_cves": host_cves
    }

    return {"scan_results": formatted_results, "summary": summary}


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
