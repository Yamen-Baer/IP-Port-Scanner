# IP and Port Scanner

## Overview

The IP and Port Scanner is a Python-based graphical user interface (GUI) application built with Tkinter. It allows users to scan active IP addresses and check the availability of specific IPs and ports. The application provides a user-friendly interface to simplify the network scanning process.

## Features

- Scan for active IP addresses in the local network.
- Check the availability of specific IP addresses.
- Scan for active ports on the local machine.
- Check the availability of specific ports.
- User-friendly GUI with loading indicators and progress bars.
- Logo and customizable application icon.

## Requirements

- Python 3.x
- Tkinter (comes pre-installed with Python)
- Pillow (for handling various image formats)
- Custom modules: `ip_scanner`, `port_scanner`, `availability_checker`

## Installation

1. Clone the repository:

   ```
   git clone https://github.com/yourusername/ip-port-scanner.git
   ```

2. Navigate to the project directory:

   ```
   cd ip-port-scanner
   ```

3. Install required packages (if using Pillow):

   ```
   pip install Pillow
   ```

4. Ensure the custom modules (`ip_scanner.py`, `port_scanner.py`, `availability_checker.py`) are in the same directory as the main application file.

## Usage

1. Run the application:

   ```
   python main.py
   ```

2. Use the "Scan Active IPs" button to find active IP addresses on your local network.
3. Enter an IP address in the "Enter IP" field to check its availability.
4. Use the "Scan Active Ports" button to find active ports.
5. Enter a port number in the "Enter Port" field to check its availability.
6. Use the "Cancel" button on the loading pop-up to abort ongoing scans.

## License

This project is open source, use it for good things only.

## Acknowledgments

- Python for Coding.
- Tkinter for the GUI framework.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue to discuss improvements or bugs.

## Contact

For questions or support, please contact [yamen.bayer.main@gmail.com] or open an issue on GitHub.
