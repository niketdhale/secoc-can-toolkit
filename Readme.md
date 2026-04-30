# AUTOSAR SecOC Simulator & CAN Toolkit

A lightweight C++17 command-line toolkit for simulating AUTOSAR Secure Onboard Communication (SecOC) over Linux SocketCAN. This project provides a cryptographic backend using OpenSSL AES-CMAC, Freshness Value management, and an AUTOSAR-inspired C API designed for BSW integration and HIL testing.

## Features

- Linux SocketCAN integration with real-time TX/RX over vcan/can interfaces
- AUTOSAR SecOC PDU wrapping and unwrapping with configurable truncation
- OpenSSL AES-128-CMAC cryptographic backend
- AUTOSAR-style C API (SecOc_Init, SecOc_Transmit, SecOc_Receive)
- Interactive command-line interface for configuration and monitoring
- Pluggable Freshness Value Manager interface (counter and timestamp modes)

## Prerequisites

| Component       | Requirement        | Arch Linux                     | Ubuntu/Debian                  |
|-----------------|--------------------|--------------------------------|--------------------------------|
| C++ Compiler    | GCC 11+ / Clang 14+| `sudo pacman -S base-devel`    | `sudo apt install build-essential` |
| Build System    | CMake 3.16+, Ninja | `sudo pacman -S cmake ninja`   | `sudo apt install cmake ninja-build` |
| Crypto Library  | OpenSSL 3.0+       | `sudo pacman -S openssl`       | `sudo apt install libssl-dev`  |
| CAN Utilities   | can-utils          | `sudo pacman -S can-utils`     | `sudo apt install can-utils`   |

## Build & Run

```bash
# Clone and navigate to the project directory
git clone https://github.com/YOUR_USERNAME/secoc-can-toolkit.git
cd secoc-can-toolkit

# Create build directory and configure
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo

# Compile
ninja

# Grant raw socket permissions (alternatively run with sudo)
sudo setcap cap_net_raw,cap_net_admin=+ep ./secoc_cli

# Launch the CLI
./secoc_cli
```

## Usage Examples
Start the CLI and follow the interactive commands:

```bash
# Open virtual CAN interface
open vcan0

# Enable SecOC and configure parameters
secoc enable
secoc config data_id=0x123 fv=4 mac=4 key=00112233445566778899AABBCCDDEEFF

# Start frame monitoring
monitor on

# Transmit a SecOC-wrapped frame
tx 123#DEADBEEF

# Test the AUTOSAR C API independently
secoc test_c_api

# Exit application
quit
```

## Project Structure
```text
secoc-can-toolkit/
├── CMakeLists.txt
├── README.md
├── LICENSE
├── include/
│   ├── CanTypes.h
│   ├── CanEngine.h
│   ├── SecOcTypes.h
│   ├── SecOcEngine.h
│   ├── FreshnessManager.h
│   └── SecOc_AutosarApi.h
├── src/
│   ├── CanEngine.cpp
│   ├── SecOcEngine.cpp
│   ├── FreshnessManager.cpp
│   └── SecOc_AutosarApi.cpp
└── apps/
    └── can_cli/
        └── main.cpp
```

## AUTOSAR Compliance Notes

| Specification Requirement | Implementation Status | Notes |
| :--- | :--- | :--- |
| **Secured PDU Structure** | Compliant | `[Header][Payload][FV][MAC]` per PRS_SecOc |
| **Big Endian Encoding** | Compliant | All FV/MAC fields serialized MSB-first |
| **AES-128-CMAC** | Compliant | OpenSSL backend (simulator grade) |
| **Freshness Anti-Replay** | Compliant | Configurable acceptance window validation |
| **Production HSM / Key Management** | Not Implemented | Requires Csm integration & secure storage |

> **Note:** This toolkit is designed for simulation, HIL testing, and educational purposes. 
> Production vehicle deployment requires certified cryptographic modules, secure key 
> provisioning, and full AUTOSAR BSW integration per ISO 21434.

MIT License. See the LICENSE file for details.
