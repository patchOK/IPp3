# IPp3 by patch

IPp3 is a simple and effective command-line tool written in Python for OT network reconnaissance. It allows you to quickly scan a range of IP addresses to find which hosts are online, continuously monitor the status of specific IP addresses, or perform detailed network analysis with comprehensive host information.

## Features
- **Scan IP Range**: Ping all IP addresses within a specified range (e.g., 192.168.1.1 to 192.168.1.100) to identify which hosts are active
- **IP Monitor**: Continuously monitor a list of specific IP addresses, providing real-time status updates (Online/Offline) in a clean, refreshing display
- **IP Monitor++**: Advanced monitoring with detailed information including:
  - Host status (Online/Offline)
  - Packet loss percentage
  - Operating system detection (approximate)
  - MAC address identification (for local network devices)
  - Open ports scanning (common and industrial protocols)
- **Cross-Platform**: Supports both Windows and Unix-like operating systems (Linux, macOS) by adapting the `ping` command
- **Multi-threaded**: Efficient scanning using concurrent threads for faster results
- **Industrial Protocol Support**: Includes scanning for industrial protocols like Modbus, EtherNet/IP, OPC UA, ProfiNet, and more

## Requirements
- Python 3.x installed on your system
- Git installed on your system

## Installation
1. **Clone the repository**: Open your terminal (Git Bash is recommended on Windows) and clone the project to your local machine:
   ```bash
   git clone https://github.com/patchOK/IPp3.git
   ```

2. **Navigate to the project directory**:
   ```bash
   cd IPp3
   ```

3. **Run the script**: You can now run the script directly from your terminal using the Python interpreter:
   ```bash
   python IPp3.py
   ```

## Usage
Upon running the script, you will be presented with an interactive menu to choose an operation:

```
~ Choose an Operation:
[1] Scan IP Range
    Syntax: START_IP END_IP (e.g. 192.168.1.1 192.168.1.10)

[2] IP Monitor  
    Syntax: IP1 IP2 IP3... (e.g. 8.8.8.8 1.1.1.1)
    Syntax: IP1 range IP2 (e.g. 1.1.1.1 range 1.1.2.1)

[3] IP Monitor++
    Syntax: IP1 IP2 IP3... (IP, Status, % Packet Loss, ≈OS, MAC Address, ≈Open Ports)
```

### Option 1: Scan IP Range
To scan a range of IPs, select option `1` and provide the starting and ending IP addresses separated by a space.

**Example:**
```
~ IP Range: 192.168.1.1 192.168.1.50
```

The script will then scan all IPs in the range and display a list of online and offline hosts in a two-column format.

### Option 2: IP Monitor
To monitor specific IPs, select option `2` and provide a list of IP addresses separated by spaces. You can also specify a range using the `range` keyword.

**Examples:**
```
~ Monitoring IP: 8.8.8.8 1.1.1.1 192.168.1.1
```
```
~ Monitoring IP: 192.168.1.1 range 192.168.1.20
```

The script will enter a continuous monitoring loop, refreshing the terminal every 1.5 seconds to show the current status of each IP.

### Option 3: IP Monitor++
This advanced monitoring mode provides comprehensive information about each host. Select option `3` and provide IP addresses separated by spaces.

**Example:**
```
~ Detailed Monitoring IP: 192.168.1.1 192.168.1.10 10.0.0.1
```

The detailed monitor displays:
- **IP Address**: Target host address
- **Status**: Online/Offline with color coding
- **% Loss**: Packet loss percentage with color indicators
- **OS**: Approximate operating system detection based on TTL values
- **MAC Address**: Hardware address (for local network devices)
- **Open Ports**: Detected open ports including common services and industrial protocols

**Industrial Protocols Detected:**
- Modbus (502)
- EtherNet/IP (44818, 2222)
- OPC UA (4840)
- ProfiNet (34962-34964)
- Siemens S7 (102)
- DNP3 (20000)
- IEC 60870-5-104 (2404)
- OMRON FINS (9600)
- Foundation Fieldbus HSE (1089, 1090)
- PCWorx (1962)

## Performance
The tool uses multithreading (up to 80 concurrent threads for range scanning, 30 for detailed monitoring) to ensure efficient and fast network analysis while maintaining system stability.

## Interrupting Operations
You can press **Ctrl+C** at any time to gracefully exit the current operation and return to the main menu or exit the program.

## Notes
- The OS detection feature provides approximate identification based on TTL values
- MAC address detection works only for devices on the local network segment
- Port scanning focuses on common services and industrial protocols
- Some features may require appropriate network permissions

## Contributing
Feel free to fork this repository and submit pull requests for any improvements or additional features!

## License
This project is open source and available under the MIT License.
