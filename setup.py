from setuptools import setup

setup(
    name='harpoon',
    version='0.1.1',
    description='Another OSINT CLI tool',
    url='https://github.com/Te-k/harpoon',
    author='Tek',
    author_email='tek@randhome.io',
    keywords='osint',
    include_package_data=True,
    dependency_links=[
        'git+https://github.com/Te-k/pycrtsh.git@master#egg=0.1#pycrtsh-0.1',
        'git+https://github.com/Te-k/pysafe.git@master#egg=pysafe-0.1',
        'git+https://github.com/Te-k/pygreynoise.git@master#egg=pygreynoise-0.1',
        'git+https://github.com/Te-k/pythreatgrid.git@master#egg=pythreatgrid-0.1',
        'git+https://github.com/Te-k/pypermacc.git@master#egg=pypermacc-0.0.1'
    ],
    install_requires=[
        'click==6.7',
        'requests',
        'configparser',
        'tweepy',
        'passivetotal',
        'beautifulsoup4',
        'lxml',
        'censys',
        'pycrtsh',
        'shodan',
        'fullcontact.py',
        'pyhunter',
        'pysafe',
        'PyGitHub',
        'telethon==0.18.3',
        'virustotal-api',
        'mispy',
        'OTXv2',
        'IPy',
        'maxminddb>=1.4.0',
        'pyasn',
        'spyonweb',
        'selenium',
        'geoip2',
        'pygreynoise',
        'dnspython',
        'pythreatgrid',
        'consolemd==0.4.4',
        'pypermacc',
        'archiveis',
        'pypdns==1.3',
        'pybinaryedge==0.2',
        'spyonweb==0.1'
        ],

    python_requires='>=3.5',
    license='GPLv3',
    packages=['harpoon', 'harpoon.commands', 'harpoon.lib', 'harpoon.data'],
    package_dir={'harpoon.lib': 'harpoon/lib'},
    package_data={'harpoon': ['harpoon/data/*.conf']},
    entry_points= {
        'console_scripts': [ 'harpoon=harpoon.main:main' ]
    }
)
