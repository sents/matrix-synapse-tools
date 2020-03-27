#!/usr/bin/env python3

# -*- coding: utf-8 -*-

from distutils.core import setup

setup(
    name="matrix-synapse-tools",
    version="0.1",
    description="""Collection of tools to make the life of a
synapse homeserver admin a bit easier.""",
    long_description="""Collection of tools to make the life of a
synapse homeserver admin a bit easier. Work in progress!
    """,
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    license="GNU GPLv3",
    install_requires=["requests", "requests-toolbelt"],
    author="Finn Krein",
    author_email="finn@krein.moe",
    url="https://github.com/sents/matrix-synapse-tools",
    packages=["matrix_synapse_tools"],
    entry_points={
        "console_scripts": [
            "corporal-policy-ldap.py = matrix_synapse_tools.__init__:main"
        ]
    },
)
