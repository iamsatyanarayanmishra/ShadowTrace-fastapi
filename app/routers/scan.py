import nmap
from fastapi import FastAPI, HTTPException, APIRouter
from datetime import datetime
from app.services import format_scan_results, is_valid_ip

router = APIRouter(prefix="/scan", tags=["Scan"])

@router.get("/advance_ip_scan/")
def deep_scan(ip: str):
    if not is_valid_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")
    nm = nmap.PortScanner()
    start_time = datetime.now()
    try:
        # nm.scan(ip, arguments='-A -sV -sC -O --script vuln')
        # nm.scan(ip, arguments='-sS -p- -A --script vuln --min-rate 500 --max-retries 2 --host-timeout 5m')
        nm.scan(ip, arguments='-sS -p- -A --script vuln --min-rate 500 --max-retries 2 --host-timeout 5m -R --dns-servers 8.8.8.8')
        scan_duration = (datetime.now() - start_time).total_seconds()
        scan_data = nm[ip]
        scan_data['scan_duration'] = scan_duration
        formatted_results = format_scan_results(scan_data)
        return formatted_results
    except nmap.PortScannerError as e:
        raise HTTPException(status_code=500, detail=f"Nmap scan failed: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")
    


@router.get("/advance_network_scan/")
def network_scan(ip: str, subnet_mask: str):
    if not is_valid_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")
    
    # Validate subnet mask (simple check)
    try:
        subnet_mask = int(subnet_mask)
        if subnet_mask < 0 or subnet_mask > 32:
            raise ValueError("Subnet mask must be between 0 and 32")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid subnet mask")

    nm = nmap.PortScanner()
    start_time = datetime.now()
    try:
        # Construct the CIDR notation from IP and subnet mask
        cidr = f"{ip}/{subnet_mask}"
        nm.scan(hosts=cidr, arguments='-sS -p- -A --script vuln --min-rate 500 --max-retries 2 --host-timeout 5m -R --dns-servers 8.8.8.8')
        scan_duration = (datetime.now() - start_time).total_seconds()
        scan_data = {host: nm[host] for host in nm.all_hosts()}  # Collect scan data for all hosts
        for host in scan_data.values():
            host['scan_duration'] = scan_duration  # Include scan duration
        formatted_results = {host: format_scan_results(scan_data[host]) for host in scan_data}
        return formatted_results
    except nmap.PortScannerError as e:
        raise HTTPException(status_code=500, detail=f"Nmap scan failed: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")
    

@router.get("/basic_ip_scan/")
def basic_scan(ip: str):
    if not is_valid_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")
    
    nm = nmap.PortScanner()
    start_time = datetime.now()
    
    try:
        # Perform a basic scan (TCP connect scan) on the specified IP
        nm.scan(ip, arguments='-sT')
        scan_duration = (datetime.now() - start_time).total_seconds()
        
        scan_data = nm[ip]
        scan_data['scan_duration'] = scan_duration
        
        formatted_results = format_scan_results(scan_data)
        return formatted_results
    
    except nmap.PortScannerError as e:
        raise HTTPException(status_code=500, detail=f"Nmap scan failed: {str(e)}")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")
    


@router.get("/basic_network_scan/")
def basic_network_scan(ip: str, subnet_mask: str):
    if not is_valid_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")
    
    try:
        subnet_mask = int(subnet_mask)
        if subnet_mask < 0 or subnet_mask > 32:
            raise ValueError("Subnet mask must be between 0 and 32")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid subnet mask")

    nm = nmap.PortScanner()
    start_time = datetime.now()
    
    try:
        cidr = f"{ip}/{subnet_mask}"
        # Perform a basic scan on all hosts in the network
        nm.scan(hosts=cidr, arguments='-sT')
        scan_duration = (datetime.now() - start_time).total_seconds()
        
        scan_data = {host: nm[host] for host in nm.all_hosts()}
        for host in scan_data.values():
            host['scan_duration'] = scan_duration
        
        formatted_results = {host: format_scan_results(scan_data[host]) for host in scan_data}
        return formatted_results
    
    except nmap.PortScannerError as e:
        raise HTTPException(status_code=500, detail=f"Nmap scan failed: {str(e)}")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")
