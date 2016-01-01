# HyperBit

HyperBit is an alternate client for the Bitmessage network. This is a very early release and should mainly be used for testing.

If you have any questions or feature requests please join the `hyperbit` channel (BM-2cUXYTknxwZgp47DKayzKwNfipQRQCmb2m). If you find any bugs be sure to report them here. I can also be reached at `BM-87ZQse4Ta4MLM9EKmfVUFA4jJUms1Fwnxws`.

The current version only supports channels (no person-to-person messages yet).

# Requirements

- Python 3.4.3 or later
- PyQt5
- quamash (requires libffi)
- cryptography (requires OpenSSL)
- appdirs
- pysocks

# Screenshots

![](../hyperbit-screenshots/linux/1.png)
![](../hyperbit-screenshots/windows/2.png)
![](../hyperbit-screenshots/linux/3.png)
![](../hyperbit-screenshots/linux/4.png)

# Windows

Install Python 3.4.4 from [https://www.python.org/downloads/release/python-344/](https://www.python.org/downloads/release/python-344/). Make sure to select "Add python.exe to Path".

Install the PyQt5 binary package from [https://riverbankcomputing.com/software/pyqt/download5](https://riverbankcomputing.com/software/pyqt/download5)

Open a command prompt and run this command:

    pip install quamash cryptography appdirs pysocks

Run HyperBit:

    python c:\path\to\hyperbit\hyperbit.py

If you receive a Windows Firewall notification, make sure to allow access.

# Debian / Ubuntu

Install dependencies:

    apt-get install python3-pip python3-pyqt5 libffi-dev libssl-dev
    pip3 install quamash cryptography appdirs pysocks

Run HyperBit:

    python3 /path/to/hyperbit/hyperbit.py

# Mac

Not officially supported but should work if you install the dependencies first. If you figure out how to do please let me know and I'll happily add the instructions.

