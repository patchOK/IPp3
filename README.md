# IPp3 by patch

## Overview
IPp3 is a simple and effective command-line tool written in Python for network reconnaissance. It allows you to quickly scan a range of IP addresses to find which hosts are online or to continuously monitor the status of a specific list of IP addresses. The program is built with multithreading to perform pings efficiently.

## Features
- **Scan IP Range:** Ping all IP addresses within a specified range (es. 192.168.1.1 to 192.168.1.100) to identify which hosts are active.
- **IP Monitor:** Continuously monitor a list of specific IP addresses, providing real-time status updates (Online/Offline) in a clean, refreshing display.
- **Cross-Platform:** Supports both Windows and Unix-like operating systems (Linux, macOS) by adapting the `ping` command.

## Installation and Setup

### Prerequisites
- Python 3.x installed on your system.
- Git installed on your system.

### Steps
1.  **Clone the repository:**
    Open your terminal (Git Bash is recommended on Windows) and clone the project to your local machine:
    ```sh
    git clone https://github.com/patchOK/IPp3.git
    ```

2.  **Navigate to the project directory:**
    ```sh
    cd IPp3
    ```

3.  **Run the script:**
    You can now run the script directly from your terminal using the Python interpreter.

## Usage

Upon running the script, you will be presented with an interactive menu to choose an operation.

```Bash
~ Chose an Operation:

[1] Scan IP Range
Syntax: START_IP END_IP (es. 192.168.1.1 192.168.1.10)

[2] IP Monitor
Syntax: IP1 IP2 IP3... (es. 8.8.8.8 1.1.1.1)
```

### Option 1: Scan IP Range
To scan a range of IPs, select option `1` and provide the starting and ending IP addresses separated by a space.

**Example:**
```Bash
~ Range IP: 192.168.1.1 192.168.1.50
```
The script will then scan all IPs in the range and display a list of online and offline hosts.

### Option 2: IP Monitor
To monitor specific IPs, select option 2 and provide a list of IP addresses separated by spaces.

Example:
```Bash
~ Monitoring IP: 8.8.8.8 1.1.1.1 192.168.1.1
```
The script will enter a continuous monitoring loop, refreshing the terminal every few seconds to show the current status of each IP. You can press Ctrl+C to exit the monitoring loop.
