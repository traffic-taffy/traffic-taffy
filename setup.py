import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="traffic-taffy",
    version="0.3.6",
    author="Wes Hardaker",
    author_email="opensource@hardakers.net",
    description="A tool for doing differential analysis of pcap files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hardaker/traffic-taffy",
    packages=setuptools.find_packages(),
    entry_points={
        "console_scripts": [
            "taffy-compare = traffic_taffy.compare:main",
            "taffy-graph = traffic_taffy.graph:main",
            "taffy-dissect = traffic_taffy.dissector:main",
            "taffy-cache-info = traffic_taffy.cache_info:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    test_suite="nose.collector",
    tests_require=["nose"],
    install_requires=[
        "pandas",
        "rich",
        "seaborn",
        "scapy",
        "dpkt",
        "pcap-parallel",
    ],
)
