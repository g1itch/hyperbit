# HyperBit

[![Quick Test](https://github.com/g1itch/hyperbit/actions/workflows/test.yml/badge.svg)](https://github.com/g1itch/hyperbit/actions/workflows/test.yml)

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

Basic idea:

    pip install -r requirements.txt
	pip install .[qt,tor]
	hyperbit
