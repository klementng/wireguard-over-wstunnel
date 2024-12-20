# Wireguard over wstunnel (TCP)

## About The Project

This is a Python application that quickly and easily enables the use of Wireguard over TCP using [wstunnel](https://github.com/erebe/wstunnel).

![alt text](images/screenshot.png)

## Getting Started

### Prerequisites

This script requires the following software to be installed/downloaded:

- [Python 3](https://www.python.org/downloads/)
- [wstunnel](https://github.com/erebe/wstunnel/releases)
- [Wireguard](https://www.wireguard.com/install/)

## Build

To create a standalone binary using PyInstaller, follow these steps:

1. Download the latest [release](https://github.com/klementng/wireguard-over-wstunnel/releases/) source code or clone the main branch.
2. Install dependencies:

   ```bash
    python -m pip install -r requirements.txt pyinstaller
   ```

3. Build the binary:

   ```bash
    pyinstaller main.py --onefile --hide-console hide-late --uac-admin
   ```

4. The output binary will be located in the `dist` directory.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Installation

#### Using PyInstaller Binaries

1. Download the latest [release](https://github.com/klementng/wireguard-over-wstunnel/releases/) binary.
2. Change permissions (for Linux systems):

    ```sh
    chmod +x ./main
    ```

3. Edit the [config.yml](./config.yml).
4. Start the program (double-click on Windows):

    ```sh
    ./main
    ```

#### Using Source Code

1. Download the latest [release](https://github.com/klementng/wireguard-over-wstunnel/releases/) source code.
2. Extract the ZIP file.
3. Install required packages:

   ```sh
   pip install -r requirements.txt
   ```

4. Edit the [config.yml](./config.yml).
5. Start the program:

   ```sh
   python main.py
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Command Line Usage

Additional Options:

```text
usage: main.py [-h] [--config CONFIG] [--clean] [--export] [--nogui] [--log_level LOG_LEVEL]

Wireguard over wstunnel

options:
  -h, --help            show this help message and exit
  --config CONFIG, -c CONFIG
                        path to program config
  --nogui               start with no GUI
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>
