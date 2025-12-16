import ipaddress
import platform
import subprocess
import concurrent.futures
import time
import sys
import os
import signal
import socket
import re
from itertools import zip_longest
import threading
import select

interrupted = False
return_to_menu = False

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    RESET = '\033[0m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'

def signal_handler(signum, frame):
    global interrupted
    interrupted = True
    print("\n~ Exiting...")

def keyboard_listener():
    """Thread che ascolta i tasti premuti per Ctrl+D"""
    global return_to_menu, interrupted
    
    system = platform.system().lower()
    
    if system == "windows":
        # Su Windows usiamo msvcrt
        import msvcrt
        while not interrupted and not return_to_menu:
            if msvcrt.kbhit():
                key = msvcrt.getch()
                if key == b'\x04':  # Ctrl+D
                    return_to_menu = True
                    print("\n~ Returning to menu...")
                    break
            time.sleep(0.1)
    else:
        # Su Linux/Mac usiamo termios e select
        import termios
        import tty
        
        old_settings = termios.tcgetattr(sys.stdin)
        try:
            tty.setcbreak(sys.stdin.fileno())
            while not interrupted and not return_to_menu:
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    char = sys.stdin.read(1)
                    if char == '\x04':  # Ctrl+D
                        return_to_menu = True
                        print("\n~ Returning to menu...")
                        break
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

def get_ping_command(ip, count=4):
    """Generate ping command based on OS"""
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", str(count), "-w", "2000", ip]
    return ["ping", "-c", str(count), "-W", "2", ip]

def parse_ping_result(result_stdout, system):
    """Parse ping output for packet loss and online status"""
    if system == "windows":
        packet_match = re.search(r'Sent = (\d+), Received = (\d+)', result_stdout)
        if packet_match:
            sent, received = map(int, packet_match.groups())
            packet_loss = ((sent - received) / sent) * 100 if sent > 0 else 100
            return received > 0, f"{packet_loss:.0f}%"
        
        online = "TTL=" in result_stdout
        return online, "0%" if online else "100%"
    else:

        loss_match = re.search(r'(\d+(?:\.\d+)?)% packet loss', result_stdout)
        if loss_match:
            packet_loss = float(loss_match.group(1))
            return packet_loss < 100, f"{packet_loss:.0f}%"
        
        packet_match = re.search(r'(\d+) packets transmitted, (\d+) (?:packets )?received', result_stdout)
        if packet_match:
            sent, received = map(int, packet_match.groups())
            packet_loss = ((sent - received) / sent) * 100 if sent > 0 else 100
            return received > 0, f"{packet_loss:.0f}%"
        
        return False, "100%"

def ping_host_detailed(ip):
    if interrupted or return_to_menu:
        return {"online": False, "packet_loss": "N/A"}
    
    system = platform.system().lower()
    command = get_ping_command(ip, 4)
    
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                              timeout=10.0, text=True)
        online, packet_loss = parse_ping_result(result.stdout, system)
        return {"online": online, "packet_loss": packet_loss}
    except subprocess.TimeoutExpired:
        return {"online": False, "packet_loss": "TIMEOUT"}
    except Exception:
        return {"online": False, "packet_loss": "ERROR"}

def ping_host(ip):
    result = ping_host_detailed(ip)
    return result["online"]

def get_os_detection(ip):
    if interrupted or return_to_menu:
        return "Unknown"
    
    system = platform.system().lower()
    command = get_ping_command(ip, 1)
    
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                              timeout=2, text=True)
        if result.returncode == 0:
            ttl_pattern = r'TTL=(\d+)' if system == "windows" else r'ttl=(\d+)'
            ttl_match = re.search(ttl_pattern, result.stdout)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                elif ttl <= 255:
                    return "Network Dev."
    except Exception:
        pass
    return "Unknown"

def get_mac_info(ip):
    if interrupted or return_to_menu:
        return {"mac": "N/A"}
    
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        if not ip_obj.is_private:
            return {"mac": "Remote"}
        
        system = platform.system().lower()

        if system != "windows":
            subprocess.run(get_ping_command(ip, 1), stdout=subprocess.PIPE, 
                         stderr=subprocess.PIPE, timeout=2)
        
        arp_cmd = ["arp", "-a", ip] if system == "windows" else ["arp", "-n", ip]
        result = subprocess.run(arp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                              timeout=3, text=True)
        
        if result.returncode == 0:
            mac_pattern = r'([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})'
            mac_match = re.search(mac_pattern, result.stdout)
            if mac_match:
                mac = mac_match.group(1).replace('-', ':').upper()
                return {"mac": mac}
        
        return {"mac": "Unknown"}
    except Exception:
        return {"mac": "Error"}

COMMON_PORTS = [
    80, 443, 22, 23, 53, 20, 21,  # Standard protocols
    102, 502, 44818, 1089, 1090, 1962, 2222, 4840,  # Industrial protocols
    9600, 20000, 34962, 34963, 34964, 2404
]

def check_common_ports(ip, ports=COMMON_PORTS):
    open_ports = []
    for port in ports:
        if interrupted or return_to_menu:
            break
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(str(port))
        except Exception:
            pass
    return ",".join(open_ports) if open_ports else "None"

def sort_ip_key(ip_str):
    try:
        return ipaddress.IPv4Address(ip_str)
    except ValueError:
        return ipaddress.IPv4Address('0.0.0.0')

def validate_ip(ip_str):
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ValueError:
        return False

def parse_ip_range(ip_list):
    if len(ip_list) == 3 and ip_list[1].lower() == 'range':
        start_ip, _, end_ip = ip_list
        if not all(validate_ip(ip) for ip in [start_ip, end_ip]):
            raise ValueError("Invalid IP addresses in range")
        
        ip_start = ipaddress.IPv4Address(start_ip)
        ip_end = ipaddress.IPv4Address(end_ip)
        
        if ip_start > ip_end:
            raise ValueError("Starting IP must be less than or equal to ending IP")
        
        return [str(ipaddress.IPv4Address(int(ip_start) + i)) 
                for i in range(int(ip_end) - int(ip_start) + 1)]
    else:
        invalid_ips = [ip for ip in ip_list if not validate_ip(ip)]
        if invalid_ips:
            raise ValueError(f"Invalid IP addresses: {', '.join(invalid_ips)}")
        return ip_list

def cancel_futures(futures):
    for future in futures:
        if not future.done():
            future.cancel()

def run_range_scan(start_ip, end_ip):
    global interrupted, return_to_menu
    interrupted = False
    return_to_menu = False
    
    if not all(validate_ip(ip) for ip in [start_ip, end_ip]):
        print(f"\n~ Error: One or both IP addresses are not valid.")
        return
    
    try:
        ip_start = ipaddress.IPv4Address(start_ip)
        ip_end = ipaddress.IPv4Address(end_ip)
        
        if ip_start > ip_end:
            print("\n~ Error: Starting IP must be less than or equal to ending IP.")
            return
        
        ip_list = [str(ipaddress.IPv4Address(int(ip_start) + i)) 
                  for i in range(int(ip_end) - int(ip_start) + 1)]
        
    except ValueError as e:
        print(f"\n~ Error: Invalid IP address. {e}")
        return
    
    if interrupted or return_to_menu:
        return
    
    total_ips = len(ip_list)
    print(f"\n~ Starting scan of {total_ips} IP addresses from {start_ip} to {end_ip}...")
    print("~ Ctrl+C to exit | Ctrl+D to return to menu\n")
    
    # Avvia il thread per ascoltare Ctrl+D
    listener_thread = threading.Thread(target=keyboard_listener, daemon=True)
    listener_thread.start()
    
    online_ips, offline_ips = set(), set()
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=80) as executor:
            future_to_ip = {executor.submit(ping_host, ip): ip for ip in ip_list}
            
            for completed, future in enumerate(concurrent.futures.as_completed(future_to_ip), 1):
                if interrupted or return_to_menu:
                    cancel_futures(future_to_ip.keys())
                    break
                
                try:
                    ip = future_to_ip[future]
                    is_online = future.result()
                    (online_ips if is_online else offline_ips).add(ip)
                    
                    percent = (completed / total_ips) * 100
                    sys.stdout.write(f'\r~ Progress: {percent:.0f}%')
                    sys.stdout.flush()
                    
                except Exception as e:
                    if not interrupted and not return_to_menu:
                        print(f"\n~ Error during ping of {future_to_ip.get(future, 'unknown')}: {e}")
                        
    except KeyboardInterrupt:
        interrupted = True
    except EOFError:
        return_to_menu = True
    
    if not interrupted and not return_to_menu:
        print("\n\n~ Scan completed.\n")
    
    if not return_to_menu:
        display_results_columns(online_ips, offline_ips)
        print(f"\n~ OK: {len(online_ips)}")
        print(f"~ NO: {len(offline_ips)}")
    
    if return_to_menu:
        print("\n~ Returning to menu...")
        time.sleep(1)

def display_results_columns(online, offline):
    if interrupted or return_to_menu:
        return
    
    online_sorted = sorted(online, key=sort_ip_key)
    offline_sorted = sorted(offline, key=sort_ip_key)
    
    print(f"{'OK':<15} | {'NO':<15}")
    print("-" * 35)
    
    for ok_ip, no_ip in zip_longest(online_sorted, offline_sorted, fillvalue=""):
        if interrupted or return_to_menu:
            break
        print(f"{ok_ip:<15} | {no_ip:<15}")

def run_monitor(ip_list):
    global interrupted, return_to_menu
    interrupted = False
    return_to_menu = False
    
    try:
        parsed_ips = parse_ip_range(ip_list)
    except ValueError as e:
        print(f"\n~ Error: {e}")
        return
    
    print(f"\n~ Starting monitoring of {len(parsed_ips)} IP addresses...")
    print("~ Ctrl+C to exit | Ctrl+D to return to menu\n")
    
    # Avvia il thread per ascoltare Ctrl+D
    listener_thread = threading.Thread(target=keyboard_listener, daemon=True)
    listener_thread.start()
    
    try:
        while not interrupted and not return_to_menu:
            statuses = {}
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(parsed_ips), 80)) as executor:
                future_to_ip = {executor.submit(ping_host, ip): ip for ip in parsed_ips}
                
                for future in concurrent.futures.as_completed(future_to_ip):
                    if interrupted or return_to_menu:
                        cancel_futures(future_to_ip.keys())
                        break
                    
                    try:
                        ip = future_to_ip[future]
                        is_online = future.result()
                        status = f"{Colors.GREEN}Online{Colors.RESET}" if is_online else f"{Colors.RED}Offline{Colors.RESET}"
                        statuses[ip] = status
                    except Exception as e:
                        if not interrupted and not return_to_menu:
                            statuses[future_to_ip[future]] = f"{Colors.YELLOW}ERROR: {str(e)[:75]}{Colors.RESET}"
            
            if interrupted or return_to_menu:
                break

            os.system('cls' if platform.system().lower() == 'windows' else 'clear')
            print(f"~ Monitoring >> {time.strftime('%H:%M:%S')}\n")
            
            for ip in parsed_ips:
                if interrupted or return_to_menu:
                    break
                status = statuses.get(ip, f"{Colors.YELLOW}~ Waiting...{Colors.RESET}")
                print(f"~ {status:<5} >> {ip}")
            
            print("\n~ Ctrl+C to exit | Ctrl+D to return to menu")
            
            for _ in range(15):
                if interrupted or return_to_menu:
                    break
                time.sleep(0.1)
                
    except KeyboardInterrupt:
        interrupted = True
    except EOFError:
        return_to_menu = True
    
    if return_to_menu:
        print("\n~ Returning to menu...")
        time.sleep(1)

def get_color_for_packet_loss(packet_loss):
    """Get color based on packet loss percentage"""
    if "%" in str(packet_loss):
        try:
            loss_value = float(packet_loss.replace("%", ""))
            if loss_value == 0:
                return f"{Colors.GREEN}{packet_loss}{Colors.RESET}"
            elif loss_value < 50:
                return f"{Colors.YELLOW}{packet_loss}{Colors.RESET}"
            else:
                return f"{Colors.RED}{packet_loss}{Colors.RESET}"
        except ValueError:
            pass
    return f"{Colors.RED}{packet_loss}{Colors.RESET}"

def get_color_for_mac(mac_address):
    """Get color for MAC address display"""
    if mac_address not in ["Unknown", "Error", "N/A", "Remote"]:
        return f"{Colors.CYAN}{mac_address}{Colors.RESET}"
    return f"{Colors.YELLOW}{mac_address}{Colors.RESET}"

def get_color_for_ports(ports):
    """Get color for ports display"""
    if ports and ports not in ["N/A", "None", "Error"]:
        return f"{Colors.GREEN}{ports[:13]}{Colors.RESET}"
    return f"{Colors.YELLOW}{ports}{Colors.RESET}"

def run_monitor_plus(ip_list):
    global interrupted, return_to_menu
    interrupted = False
    return_to_menu = False
    
    try:
        parsed_ips = parse_ip_range(ip_list)
    except ValueError as e:
        print(f"\n~ Error: {e}")
        return
    
    print(f"\n~ Starting detailed monitoring of {len(parsed_ips)} IP addresses...")
    print("~ Ctrl+C to exit | Ctrl+D to return to menu\n")
    
    # Avvia il thread per ascoltare Ctrl+D
    listener_thread = threading.Thread(target=keyboard_listener, daemon=True)
    listener_thread.start()
    
    try:
        while not interrupted and not return_to_menu:
            detailed_results = {}
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(parsed_ips), 30)) as executor:

                ping_futures = {executor.submit(ping_host_detailed, ip): ip for ip in parsed_ips}
                os_futures = {executor.submit(get_os_detection, ip): ip for ip in parsed_ips}
                mac_futures = {executor.submit(get_mac_info, ip): ip for ip in parsed_ips}
                port_futures = {}

                for future in concurrent.futures.as_completed(ping_futures):
                    if interrupted or return_to_menu:
                        cancel_futures(list(ping_futures.keys()) + list(os_futures.keys()) + 
                                     list(mac_futures.keys()) + list(port_futures.keys()))
                        break
                    
                    try:
                        ip = ping_futures[future]
                        ping_result = future.result()
                        detailed_results[ip] = ping_result.copy()
                        
                        if ping_result.get("online", False):
                            port_futures[executor.submit(check_common_ports, ip)] = ip
                        
                        sys.stdout.write(f'Scanning: {ip}\n')
                        sys.stdout.flush()
                        
                    except Exception:
                        detailed_results[ip] = {"online": False, "packet_loss": "ERROR"}
                
                if interrupted or return_to_menu:
                    break

                all_futures = [(os_futures, "os"), (mac_futures, "mac_address"), (port_futures, "ports")]
                
                for futures_dict, key in all_futures:
                    for future in concurrent.futures.as_completed(futures_dict):
                        if interrupted or return_to_menu:
                            break
                        try:
                            ip = futures_dict[future]
                            result = future.result()
                            if ip in detailed_results:
                                if key == "mac_address":
                                    detailed_results[ip][key] = result.get("mac", "Error")
                                else:
                                    detailed_results[ip][key] = result
                        except Exception:
                            if ip in detailed_results:
                                detailed_results[ip][key] = "Error" if key != "mac_address" else "Error"

                for ip in parsed_ips:
                    if ip in detailed_results and not detailed_results[ip].get("online", False):
                        detailed_results[ip]["ports"] = "N/A"
            
            if interrupted or return_to_menu:
                break

            os.system('cls' if platform.system().lower() == 'windows' else 'clear')
            print(f"~ IP Monitor++ >> {time.strftime('%H:%M:%S')}\n")
            print(f"{'IP Address':<15} | {'Status':<8} | {'% Loss':<8} | {'OS':<12} | {'MAC Address':<17} | {'Open Ports':<15}")
            print("-" * 85)
            
            for ip in parsed_ips:
                if interrupted or return_to_menu:
                    break
                
                result = detailed_results.get(ip, {
                    "online": False, "packet_loss": "Waiting...", "os": "Unknown",
                    "mac_address": "Unknown", "ports": "N/A"
                })
                
                status = f"{Colors.GREEN}Online{Colors.RESET}" if result.get("online", False) else f"{Colors.RED}Offline{Colors.RESET}"
                packet_display = get_color_for_packet_loss(result.get("packet_loss", "N/A"))
                mac_display = get_color_for_mac(result.get("mac_address", "Unknown"))
                ports_display = get_color_for_ports(result.get("ports", "N/A"))
                
                print(f"{ip:<15} | {status:<17} | {packet_display:<17} | {result.get('os', 'Unknown'):<12} | {mac_display:<26} | {ports_display}")
            
            print("-" * 85)
            print("\n~ Ctrl+C to exit | Ctrl+D to return to menu\n")
            
            for _ in range(15):
                if interrupted or return_to_menu:
                    break
                time.sleep(0.1)
                
    except KeyboardInterrupt:
        interrupted = True
    except EOFError:
        return_to_menu = True
    
    if return_to_menu:
        print("\n~ Returning to menu...")
        time.sleep(1)

def main():
    global interrupted, return_to_menu
    signal.signal(signal.SIGINT, signal_handler)
    
    while True:
        interrupted = False
        return_to_menu = False
        
        try:
            asci_name = r"""
 ___  ________  ________  ________     
|\  \|\   __  \|\   __  \|\_____  \    
\ \  \ \  \|\  \ \  \|\  \|____|\ /_   
 \ \  \ \   ____\ \   ____\    \|\  \  
  \ \  \ \  \___|\ \  \___|   __\_\  \ 
   \ \__\ \__\    \ \__\     |\_______\
    \|__|\|__|     \|__|     \|_______|
                                                                                                              
"""
            print(asci_name)
            print("[1] Scan IP Range (range)")
            print("    Syntax: START_IP END_IP (e.g. 192.168.1.1 192.168.1.10)\n")
            print("[2] IP Monitor (monitor)")
            print("    Syntax: IP1 IP2 IP3... (e.g. 8.8.8.8 1.1.1.1)")
            print("    Syntax: IP1 range IP2 (e.g. 1.1.1.1 range 1.1.2.1)\n")
            print("[3] IP Monitor++ (monitor++)")
            print("    Syntax: IP1 IP2 IP3... (IP, Status, % Packet Loss, ≈OS, MAC Address, ≈Open Ports)\n")
            
            choice = input("~ ").strip()
            if interrupted:
                break
            
            if choice == '1' or choice == 'range':
                range_input = input("~ IP Range: ").strip().split()
                if not interrupted and len(range_input) == 2:
                    start_ip, end_ip = range_input
                    run_range_scan(start_ip, end_ip)
                    if interrupted and not return_to_menu:
                        break
                elif not interrupted:
                    print("\n~ Error: You must enter exactly two IP addresses separated by a space.")
            
            elif choice == '2' or choice == 'monitor':
                monitor_input = input("~ Monitoring IP: ").strip().split()
                if not interrupted and monitor_input:
                    run_monitor(monitor_input)
                    if interrupted and not return_to_menu:
                        break
                elif not interrupted:
                    print("\n~ Error: You must enter at least one IP address.")
            
            elif choice == '3' or choice == 'monitor++':
                monitor_input = input("~ Detailed Monitoring IP: ").strip().split()
                if not interrupted and monitor_input:
                    run_monitor_plus(monitor_input)
                    if interrupted and not return_to_menu:
                        break
                elif not interrupted:
                    print("\n~ Error: You must enter at least one IP address.")
            else:
                if not interrupted:
                    print("\n~ Invalid choice.")
                    
        except KeyboardInterrupt:
            interrupted = True
            break
        except EOFError:
            return_to_menu = True
            continue
        except Exception as e:
            if not interrupted:
                print(f"\n~ An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
