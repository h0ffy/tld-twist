# not tested
from setuptools import setup, find_packages

setup(
    name="tld-twist",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "simple-colors",
        "tqdm",
        "pyfiglet"
    ],
    entry_points={
        "console_scripts": [
            "tld-twist=tld-twist:main",
        ],
    },
    package_data={
        "tld-twist": ["*.json", "*.yaml", "*.yml"],
    },
    include_package_data=True,
    author="h0ffy // JennyLab",
    author_email="h0ffy@jenny.cat",
    description="tld-twist - Deep Learning Side Channel Attacks",
    long_description="tld-twist is a framework for Deep Learning Side Channel Attacks.",
    long_description_content_type="text/markdown",
    url="https://github.com/h0ffy/tld-twist/blob/main/README.md?raw=true",
    license="Public Domain",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: Public Domain",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    keywords="deep learning side channel attacks",
    project_urls={
        "Bug Tracker": "https://github.com/h0ffy/tld-twist/issues",
        "Documentation": "https://github.com/h0ffy/tld-twist/wiki",
        "Source Code": "https://github.com/h0ffy/tld-twist.git",
        "Changelog": "https://github.com/h0ffy/tld-twist/blob/main/CHANGELOG.md?raw=true",
        "Contributing": "JennyLab",
        "License": "Public Domain",
        "Support": "DiY",
        "Author": "h0ffy // JennyLab",
        "Author Email": "h0ffy@jenny.cat",
        "Author URL": "https://www.jennylab.net",
        "Author GitHub": "https://github.com/h0ffy"
    }    
)