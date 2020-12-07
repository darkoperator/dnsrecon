import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="reconDNS",
    version="0.0.2",
    author="@SecurityShrimp",
    description="DNS Enumeration Script",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/f8al/dnsrecon",
    packages=setuptools.find_packages(),
    requires=['dnspython',
              'netaddr',
              'lxml',
              'flake8'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    data_files=[],
)
