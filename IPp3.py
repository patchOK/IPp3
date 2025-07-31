# IPp3
import ipaddress
import platform
import subprocess
import concurrent.futures
import time
import sys
import os
import signal
from itertools import zip_longest

interrupted = False

def signal_handler(signum, frame):
    global interrupted
    interrupted = True
    print("\n~ Exiting...")

def ping_host(ip):
    if interrupted:
        return False
    
    system = platform.system().lower()
    
    if system == "windows":
        command = ["ping", "-n", "1", "-w", "2000", str(ip)]
        timeout = 3.0
    else:
        command = ["ping", "-c", "1", "-W", "2", str(ip)]
        timeout = 3.0
    
    try:
        result = subprocess.run(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            timeout=timeout,
            text=True
        )
        
        if result.returncode == 0:
            if system == "windows":
                return "TTL=" in result.stdout
            else:
                return "1 packets transmitted, 1 received" in result.stdout or "1 packets transmitted, 1 packets received" in result.stdout
        
        return False
        
    except subprocess.TimeoutExpired:
        return False
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        print(f"~ Error: ping command not found on system")
        return False
    except Exception as e:
        print(f"~ Error during ping of {ip}: {e}")
        return False

def sort_ip_key(ip_str):
    try:
        return ipaddress.IPv4Address(ip_str)
    except ValueError:
        return ipaddress.IPv4Address('0.0.0.0')

def cancel_futures(future_to_ip):
    for f in future_to_ip:
        if not f.done():
            f.cancel()

def validate_ip(ip_str):
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ValueError:
        return False

def run_range_scan(start_ip, end_ip):
    global interrupted
    
    if not validate_ip(start_ip) or not validate_ip(end_ip):
        print(f"\n~ Error: One or both IP addresses are not valid.")
        return
    
    try:
        ip_start_obj = ipaddress.IPv4Address(start_ip)
        ip_end_obj = ipaddress.IPv4Address(end_ip)
    except ValueError as e:
        print(f"\n~ Error: Invalid IP address. {e}")
        return

    if ip_start_obj > ip_end_obj:
        print("\n~ Error: Starting IP must be less than or equal to ending IP.")
        return
    
    ip_list = []
    current_ip = ip_start_obj
    while current_ip <= ip_end_obj and not interrupted:
        ip_list.append(str(current_ip))
        current_ip += 1
    
    if interrupted:
        return
    
    total_ips = len(ip_list)
    print(f"\n~ Starting scan of {total_ips} IP addresses from {start_ip} to {end_ip}...")
    print("~ Ctrl+C to exit\n")

    online_ips = []
    offline_ips = []
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {executor.submit(ping_host, ip): ip for ip in ip_list}
            
            completed = 0
            for future in concurrent.futures.as_completed(future_to_ip):
                if interrupted:
                    cancel_futures(future_to_ip)
                    break
                    
                try:
                    ip = future_to_ip[future]
                    is_online = future.result()
                    
                    if is_online:
                        online_ips.append(ip)
                    else:
                        offline_ips.append(ip)
                    
                    completed += 1
                    percent = (completed / total_ips) * 100
                    bar_length = 50
                    filled_len = int(bar_length * completed // total_ips)
                    bar = '█' * filled_len + '-' * (bar_length - filled_len)
                    sys.stdout.write(f'\r~ Progress: |{bar}| {percent:.1f}% Complete')
                    sys.stdout.flush()
                except Exception as e:
                    if not interrupted:
                        completed += 1
                        print(f"\n~ Error during ping of {future_to_ip.get(future, 'unknown')}: {e}")
    except KeyboardInterrupt:
        interrupted = True
        
    if not interrupted:        
        print("\n\n~ Scan completed.\n")

    display_results_columns(online_ips, offline_ips)

def display_results_columns(online, offline):
    if interrupted:
        return
        
    online.sort(key=sort_ip_key)
    offline.sort(key=sort_ip_key)
    
    print(f"{'OK':<15} | {'NO':<15}")
    print("-" * 35)
    
    for ok_ip, no_ip in zip_longest(online, offline, fillvalue=""):
        if interrupted:
            break
        print(f"{ok_ip:<15} | {no_ip:<15}")

def run_monitor(ip_list):
    global interrupted
    
    invalid_ips = [ip for ip in ip_list if not validate_ip(ip)]
    if invalid_ips:
        print(f"\n~ Error: The following IPs are not valid: {', '.join(invalid_ips)}")
        return
    
    print(f"\n~ Starting monitoring of {len(ip_list)} IP addresses...")
    print("~ Ctrl+C to exit\n")
    
    try:
        while not interrupted:
            statuses = {}
            
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ip_list), 20)) as executor:
                    future_to_ip = {executor.submit(ping_host, ip): ip for ip in ip_list}
                    
                    for future in concurrent.futures.as_completed(future_to_ip):
                        if interrupted:
                            cancel_futures(future_to_ip)
                            break
                            
                        try:
                            ip = future_to_ip[future]
                            is_online = future.result()
                            statuses[ip] = "OK" if is_online else "NO"
                        except Exception as e:
                            if not interrupted:
                                statuses[future_to_ip[future]] = f"ERROR: {str(e)[:20]}"
            except KeyboardInterrupt:
                interrupted = True
                break
            
            if interrupted:
                break
                
            try:
                os.system('cls' if platform.system().lower() == 'windows' else 'clear')
                
                print(f"~ Monitoring - {time.strftime('%H:%M:%S')}\n")
                print("-" * 25)
                
                for ip in ip_list:
                    if interrupted:
                        break
                    status = statuses.get(ip, "~ Waiting...")
                    print(f"~ {ip:<15} >> {status}")
                        
                print("-" * 25)
                print("\n~ Ctrl+C to exit")
                
            except Exception as e:
                if not interrupted:
                    print(f"~ Error during display: {e}")
            
            for _ in range(20):
                if interrupted:
                    break
                time.sleep(0.1)
                
    except KeyboardInterrupt:
        interrupted = True

def main():
    global interrupted
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        asci_name = r"""
  _____ _____      ____  
 |_   _|  __ \    |___ \ 
   | | | |__) | __  __) |
   | | |  ___/ '_ \|__ < 
  _| |_| |   | |_) |__) |
 |_____|_|   | .__/____/ 
             | |         
             |_|                                                                                  
"""
        print(asci_name)
        print("-" * 60)
        print("\n~ Choose an operation:\n")
        print("[1] Scan IP Range")
        print("    Syntax: START_IP END_IP (e.g. 192.168.1.1 192.168.1.10)\n")
        print("[2] IP Monitor")
        print("    Syntax: IP1 IP2 IP3... (e.g. 8.8.8.8 1.1.1.1)\n")
        print("-" * 60)

        choice = input("~ ").strip()
        
        if interrupted:
            return
            
        if choice == '1':
            range_input = input("~ IP Range: ").strip().split()
            if not interrupted and len(range_input) == 2:
                start_ip, end_ip = range_input
                run_range_scan(start_ip, end_ip)
            elif not interrupted:
                print("\n~ Error: You must enter exactly two IP addresses separated by a space.")

        elif choice == '2':
            monitor_input = input("~ Monitoring IP: ").strip().split()
            if not interrupted and monitor_input:
                run_monitor(monitor_input)
            elif not interrupted:
                print("\n~ Error: You must enter at least one IP address.")
        else:
            if not interrupted:
                print("\n~ Invalid choice.")
            
    except KeyboardInterrupt:
        interrupted = True
    except Exception as e:
        if not interrupted:
            print(f"\n~ An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
