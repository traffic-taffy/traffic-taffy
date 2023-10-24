import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pcap-compare",
    version="0.1",
    author="Wes Hardaker",
    author_email="opensource@hardakers.net",
    description="A tool for doing differential analysis of pcap files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hardaker/pcap-compare",
    packages=setuptools.find_packages(),
    entry_points={
        "console_scripts": [
            "pcap-compare = pcap_compare.compare:main",
            "pcap-graph = pcap_compare.graph:main",
            "pcap-dissect = pcap_compare.dissector:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    test_suite="nose.collector",
    tests_require=["nose"],
)
