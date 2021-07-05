import os
from setuptools import setup, Extension
import subprocess

cryptera_module = Extension(
    'cryptera',
    sources=["libdec.c"],
    libraries     = ['gcrypt', 'uuid'],
)
setup(
    version="1.0",
    name="cryptera",
    description="Cryptera module for encoding/decoding payloads",
    ext_modules=[cryptera_module])
