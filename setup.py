from setuptools import setup

setup(
    name='harpoon',
    version='0.1',
    description='Another OSINT CLI tool',
    url='https://github.com/Te-k/harpoon',
    author='Tek',
    author_email='tek@randhome.io',
    keywords='osint',
    install_requires=['requests', 'configparser', 'tweepy'],
    license='GPLv3',
    packages=['harpoon', 'harpoon.commands'],
    entry_points= {
        'console_scripts': [ 'harpoon=harpoon.main:main' ]
    }
)
