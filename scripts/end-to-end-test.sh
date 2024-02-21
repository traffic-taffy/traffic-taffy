#!/bin/bash

p.() {
    prog=${1}
    shift

    echo ""
    echo "------ taffy-${prog} $*"
    time PYTHONPATH=. python traffic_taffy/tools/${prog}.py $*

    if [ $? != 0 ] ; then
        echo "FAILED!"
        echo "CMD: PYTHONPATH=. python traffic_taffy/tools/${prog}.py $*"
        exit 1
    fi
}

for level in 1 2 3 10 ; do

    # straight dissection
    p. dissect -d $level -c 100 -n 1000 test.pcap

    # with caching
    rm -f *.e2etest*
    p. dissect -d $level -c 100 -C --cs e2etest.$level -n 1000 test.pcap

    # use cache
    p. dissect -d $level -c 100 -C --cs e2etest.$level -n 1000 test.pcap

    # use memorized parts of cache
    p. dissect -d $level -c 100 -C --cs e2etest.$level test.pcap

    # check cache
    p. cache_info test.pcap.e2etest.$level

    # compare two files no args
    p. compare -d $level -C --cs e2etest.$level test.pcap test.pcap

    # compare two files restricted comparison
    p. compare -d $level -C --cs e2etest.$level -c 100 -x 10 -t 10 test.pcap test.pcap

done

# TBD: check failure cases (bad caches, etc)
