from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='harpoon',
    version='0.1.4',
    description='Another OSINT CLI tool',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/Te-k/harpoon',
    author='Tek',
    author_email='tek@randhome.io',
    keywords='osint',
    include_package_data=True,
    install_requires=[
        'click==6.7',
        'requests',
        'configparser',
        'tweepy',
        'passivetotal',
        'beautifulsoup4==4.7.0',
        'lxml==4.2.6',
        'censys',
        'shodan',
        'fullcontact.py',
        'pyhunter',
        'PyGitHub',
        'telethon==0.18.3',
        'virustotal-api',
        'mispy',
        'OTXv2',
        'IPy',
        'maxminddb>=1.4.0',
        'pyasn',
        'spyonweb==0.1',
        'selenium',
        'geoip2',
        'pygreynoisev1==0.1',
        'dnspython',
        'consolemd==0.4.4',
        'pypermacc==0.1.1',
        'archiveis',
        'pytz',
        'pypdns==1.3',
        'pybinaryedge==0.5',
        'spyonweb==0.1',
        'pythreatgrid2==0.1.1',
        'pycrtsh==0.3.1',
        'pysafebrowsing==0.1.1',
        'dnsdb==0.2.5'
        ],
    python_requires='>=3.5',
    license='GPLv3',
    packages=['harpoon', 'harpoon.commands', 'harpoon.lib', 'harpoon.data'],
    package_dir={'harpoon.lib': 'harpoon/lib'},
    package_data={'harpoon': ['harpoon/data/*.conf']},
    entry_points= {
        'console_scripts': [ 'harpoon=harpoon.main:main' ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)
