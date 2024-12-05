#DCX-System-Collector
This program is a command-line interface (CLI) tool that collects and displays various information about the machine and operating system it is running on. The information is retrieved based on the command-line arguments provided when the program is executed.

How to Use
To run the program, provide one of the supported arguments as a command-line parameter. The program will output the requested information to the terminal.

Example Usage
sh
```
./system-collector get_hostname
```

Supported Commands
```
get_hostname          - Returns the hostname of the machine.
get_os_short          - Returns a brief description of the operating system.
get_os                - Returns detailed information about the operating system.
get_cpu_short         - Returns a brief description of the CPU.
get_cpu               - Returns detailed information about the CPU.
get_mb_short          - Returns a brief description of the motherboard.
get_mb                - Returns detailed information about the motherboard.
get_ram_short         - Returns a brief description of the RAM.
get_ram               - Returns detailed information about the RAM.
get_disks             - Returns information about the available disks.
get_partitions        - Returns information about disk partitions.
get_networks          - Returns information about network interfaces.
get_processes         - Returns a list of running processes.
get_serial            - Returns the serial number of the machine.
get_mb_serial         - Returns the serial number of the motherboard.
get_mac_1             - Returns the MAC address of the first network interface.
get_mac_2             - Returns the MAC address of the second network interface.
get_hw_short          - Returns a summary of motherboard, CPU, and RAM information.
get_installed_programs - Returns a list of installed programs.
get_hw                - Returns a detailed summary of hardware and network information.
```

for now, just work on windows
