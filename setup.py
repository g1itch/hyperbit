# Copyright 2015-2016 HyperBit developers

import setuptools

setuptools.setup(
    name='HyperBit',
    version='0.1.0',
    description='Alternate client for the Bitmessage network',
    author='HyperBit developers',
    url='https://github.com/mirrorwish/hyperbit',
    packages=['hyperbit', 'hyperbit.gui', 'hyperbit/gui/data'],
    package_data={
        '': ['*.ui']
    },
    entry_points={
        'console_scripts': [
            'hyperbit = hyperbit.main:main'
        ]
    }
)

