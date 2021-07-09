# Copyright 2015-2021 HyperBit developers

import os

from setuptools import setup

from hyperbit import __version__


topdir = os.path.abspath(os.path.dirname(__file__))

requirements = list(open(
    os.path.join(topdir, 'requirements.txt'), encoding='utf8').readlines())

long_description = open(
    os.path.join(topdir, 'README.md'), encoding='utf8').read()

setup(
    name='HyperBit',
    version=__version__,
    description='Alternate client for the Bitmessage network',
    author='HyperBit developers',
    license='MIT',
    url='https://github.com/g1itch/hyperbit',
    packages=['hyperbit', 'hyperbit.gui'],
    package_data={'': ['hyperbit/gui/data/*.ui']},
    entry_points={
        'console_scripts': ['hyperbit = hyperbit.main:main']},
    install_requires=requirements,
    python_requires='>=3.6',  # qasync requirement
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: X11 Applications :: Qt',
        'Intended Audience :: Developers',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: MIT License'
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
    ]
)
