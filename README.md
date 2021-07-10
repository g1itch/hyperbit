# HyperBit

HyperBit is an alternate client for the Bitmessage network. This is a very early
release and should mainly be used for testing.

If you have any questions or feature requests please join the `[chan] hyperbit`
(BM-2cUXYTknxwZgp47DKayzKwNfipQRQCmb2m). If you find any bugs be sure to report
them here. I can also be reached at `BM-NC4h7r3HGcJgqNuwSEpGcSiVij3BKuXa`.

The current version only supports channels (no person-to-person messages yet)
and simple or trivial encoding (no msgpack).

# Requirements

- Python 3.6 or later
- PyQt5
- qasync
- cryptography (requires OpenSSL)
- appdirs
- pysocks

# Installation

## Debian / Ubuntu

Install dependencies:

    apt-get install python3-pip libqt5widgets5
    pip3 install -r requirements.txt

Run HyperBit:

    python3 /path/to/hyperbit/hyperbit.py

## Windows

Install Python 3.8 from [https://www.python.org/downloads/release/python-3810/](https://www.python.org/downloads/release/python-3810/).
Make sure to select "Add python.exe to Path".

Open a command prompt and run this command:

    pip install -r requirements.txt

Run HyperBit:

    python c:\path\to\hyperbit\hyperbit.py

If you receive a Windows Firewall notification, make sure to allow access.

## Mac

Not officially supported but should work if you install the dependencies first.
If you figure out how to do please let me know and I'll happily add the
instructions.

