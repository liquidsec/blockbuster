# blockbuster

![License](https://img.shields.io/badge/license-GPLv3-f126ea.svg)
![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![Tests](https://github.com/liquidsec/blockbuster/actions/workflows/tests.yaml/badge.svg?branch=main)

A python-based padding oracle exploitation tool.

Although several other padding oracle attack tools exist, some quite excellent, there are relatively few written in python. This tool provides another take on attacking padding oracle vulnerabilities with a handful of less common advanced features.

## Features

- **Async Concurrency** - Solve bytes with up to 256 concurrent requests for massive speed improvements
- **Fault Tolerance** - Configurable confirmation rounds to eliminate false positives from unreliable oracles
- **Resume** - Full state serialization to disk. Stop and resume at any point, including mid-block byte-level resume
- **Encrypt & Decrypt** - Both CBC padding oracle decryption and encryption (via intermediary values)
- **HTTP Proxy Support** - Route traffic through Burp, mitmproxy, etc.
- **Positive and Negative Oracle Modes** - Search for a string on valid padding, or detect its absence
- **Multiple IV Modes** - First block (most common), known IV, unknown IV, or anchor block
- **Multiple Encoding Modes** - Base64, Base64URL, and Hex
- **Multiple Input Modes** - URL parameter, query string, cookie, or POST body
- **Redirect Following** - Manual redirect following with configurable delay between hops
- **HTTP/2 Support** - Via httpx with h2
- **Pre-seeded Intermediates** - Skip known bytes from a previous partial run

## Installation

```bash
pip install poetry
poetry install
```

## Usage

```
usage: blockbuster [-h] [-r RESTORE] [-i INPUT] [-m MODE] [-d] [-c CONFIG] [-s INTERMEDIATES]

optional arguments:
  -h, --help            show this help message and exit
  -r RESTORE, --restore RESTORE
                        Specify a state file to restore from
  -i INPUT, --input INPUT
                        Specify either the ciphertext (for decrypt) or
                        plaintext (for encrypt)
  -m MODE, --mode MODE  Select encrypt (e) or decrypt (d) mode
  -d, --debug           increase output verbosity
  -c CONFIG, --config CONFIG
                        Specify the configuration file
  -s INTERMEDIATES, --intermediates INTERMEDIATES
                        Pre-seed solved intermediate values. Format: "15:210,14:216"
```

Blockbuster is designed around the creation of a configuration file for each unique job. The goal is to frontload the configuration so that once it is set correctly, exploitation occurs with a concise CLI command.

### Quick Start

```bash
# Decrypt mode
blockbuster -m d -i "BASE64_CIPHERTEXT" -c target.ini

# Encrypt mode
blockbuster -m e -i "plaintext to encrypt" -c target.ini

# Resume a saved state
blockbuster -r blockbuster-state-job-BLOCK_2-1710000000.pkl

# Resume with pre-seeded intermediates from a previous run
blockbuster -r blockbuster-state-job-BLOCK_2-1710000000.pkl -s "15:210,14:55,13:128"
```

## Configuration

See `example.ini` for a fully commented configuration file. Key settings:

| Setting | Description |
|---------|-------------|
| `URL` | Target URL |
| `httpMethod` | `GET` or `POST` |
| `inputMode` | `parameter`, `querystring`, `cookie` |
| `encodingMode` | `base64`, `base64Url`, `hex` |
| `vulnerableParameter` | Name of the parameter containing the ciphertext |
| `blocksize` | Block size (8 for DES/3DES, 16 for AES) |
| `oracleMode` | `search` (text present = valid) or `negative` (text absent = valid) |
| `oracleText` | The string to search for in the response |
| `ivMode` | `firstblock`, `knownIV`, `unknown`, or `anchorBlock` |
| `concurrency` | Number of concurrent async requests per byte (1-256) |
| `confirmations` | Re-verification rounds per solved byte (0 = none) |
| `followRedirects` | Follow HTTP redirects manually |
| `redirectDelay` | Seconds to wait before following each redirect |

## Running Tests

```bash
poetry install --with test
poetry run pytest tests/ -q
```
