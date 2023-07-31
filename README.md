# Wireguard over wstunnel (TCP)


## About The Project

This is a python script that quickly and easily enables the use of wireguard over TCP using [wstunnel](https://github.com/erebe/wstunnel)

Use cases:
- Obfuscate wireguard as http traffic
- Bypass firewalls


## Getting Started

### Prerequisites 
This script require the following software to be installed / downloaded:
  - [python3](https://www.python.org/downloads/)
  - [wstunnel](https://github.com/erebe/wstunnel/releases)
  - [wireguard](https://www.wireguard.com/install/)

### Installation

_Installing required packages_

1. Clone the repo
   ```sh
   git clone https://github.com/klementng/wireguard-over-wstunnel.git
   ```
2. Change directory
   ```sh
   cd wireguard-over-wstunnel/
   ```
3. Install required packages
   ```sh
   pip install -r requirements.txt 
   ```
4. Download [wstunnel](https://github.com/erebe/wstunnel/releases/)
   ```sh
   wget https://github.com/erebe/wstunnel/releases/download/v5.0/wstunnel-linux-x64
   ```
5. Change permission on file
   ```sh
   chmod +x wstunnel-linux-x64
   ```

 _Using pyinstaller precomplied binaries_

1. Download latest [release](https://github.com/klementng/wireguard-over-wstunnel/releases/)
2. Download [wstunnel](https://github.com/erebe/wstunnel/releases)
3. Change permissions (for linux systems)
    ```sh
    chmod +x ./main 
    ```
4. Start the program (double click on windows)
    ```sh
    ./main 
    ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>


## Usage

Setup the yaml config and start the server

1. Edit the [config.yml](./config.yml)
2. Start the program

```sh
python main.py
```

Additional Options:

```sh
usage: main.py [-h] [--config CONFIG] [--clean]

Wireguard over wstunnel

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG, -c CONFIG
                        Path to program config
  --clean               Clean wireguard tunnel that are not properly stopped
  --log_level LOG_LEVEL
                        Set logging level

```

<p align="right">(<a href="#readme-top">back to top</a>)</p>


## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>
