from setuptools import setup, find_packages

setup(
    name="advanced-packet-analyzer",
    version="3.0.0",
    description="Advanced network packet analyzer with interactive TUI",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Your Name",
    author_email="you@example.com",
    url="https://github.com/yourusername/advanced-packet-analyzer",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "scapy>=2.5.0",
        "textual>=0.47.0",
        "rich>=13.7.0",
        "pyyaml>=6.0",
        "psutil>=5.9.0",
        "python-dotenv>=1.0.0",
        "orjson>=3.9.0",
    ],
    extras_require={
        "fast": ["uvloop>=0.19.0"],
        "dev": ["pytest>=7.4.0", "pytest-asyncio>=0.21.0", "pytest-cov>=4.1.0"],
    },
    entry_points={
        "console_scripts": [
            "pktanalyzer=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
)
