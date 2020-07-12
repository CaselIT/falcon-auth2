from pathlib import Path
import re
from setuptools import setup, find_packages

README = (Path() / "README.md").read_text()

_init = (Path() / "falcon_auth2" / "__init__.py").read_text()
VERSION = re.compile(r""".*__version__ = ["'](.*?)['"]""", re.S).match(_init).group(1)

REQUIRES = [
    "falcon >= 2",
]

setup(
    name="falcon-auth2",
    version=VERSION,
    description="Falcon authentication middleware that supports multiple authentication types. ",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Federico Caselli",
    author_email="cfederico87+pypi@gmail.com",
    url="https://github.com/CaselIT/falcon-auth2",
    license="Apache-2.0",
    packages=find_packages("."),
    install_requires=REQUIRES,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="wsgi web api middleware auth authentication",
)
