import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="dnsrecon",
    version="1.0.2",
    author="Carlos Perez",
    author_email="carlos_perez@darkoperator.com",
    description="DNS Enumeration Script",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/darkoperator/dnsrecon",
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
    data_files=[
        ('/etc/dnsrecon', [
            './dictionary/snoop.txt',
            './dictionary/subdomains-top1mil-20000.txt',
            './dictionary/subdomains-top1mil-5000.txt',
            './dictionary/subdomains-top1mil.txt',
            './dictionary/namelist.txt']
        )
    ],
)
