import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="dnsrecon",
    version="1.1.0",
    author="Carlos Perez",
    author_email="carlos_perez@darkoperator.com",
    description="DNS Enumeration Script",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/darkoperator/dnsrecon",
    packages=setuptools.find_packages(exclude=["tests"]),
    python_requires='>=3.7',
    entry_points={
        "console_scripts": [
            "dnsrecon = dnsrecon.__main__:main"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: OS Independent",
    ],
    data_files=[
        ('/etc/dnsrecon', [
            'namelist.txt',
            'snoop.txt',
            'subdomains-top1mil-20000.txt',
            'subdomains-top1mil-5000.txt',
            'subdomains-top1mil.txt',
        ]
        )
    ],
)
