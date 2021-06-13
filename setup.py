#!/usr/bin/env python3

from aeroot import __version__
from os import path
from setuptools import setup, find_packages

main_dir = path.abspath(path.dirname(__file__))
install_requires = open(path.join(main_dir, "requirements.txt"), "r").readlines()
long_description = open(path.join(main_dir, "README.md"), "r", encoding="utf-8").read()
packages = find_packages(exclude=["*.tests", "*.tests.*", "test*", "tests"])
packages.append("config")

setup(
    name="aeroot",
    version=__version__,
    packages=packages,
    url="https://github.com/quarkslab/AERoot",
    license="Apache License 2.0",
    author="Eric Le Guevel (ha0)",
    author_email="eleguevel@quarkslab.com",
    description="Android Emulator Rooting system",
    long_description=long_description,
    long_description_content_type="text/markdown",
    install_requires=install_requires,
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "aeroot=aeroot.cli:main",
        ]
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Security",
        "Topic :: Utilities",
    ]
)
