#!/bin/bash

usage() {
    echo "usage: $0 [-l level[s]]"
    exit 1
}

levels="1 2 3 10"

while getopts "l:h" arg ; do
    case $arg in
	l) levels=$OPTARG ;;
	h) usage ;;
	*) usage ;;
    esac
done
shift $(($OPTIND - 1))

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

# clean slate testing
rm -rf test-outputs
rm -f *.e2etest*
mkdir -p test-outputs

for level in $levels ; do

    # straight dissection
    p. dissect -d $level -c 100 -n 1000 test.pcap

    # with caching
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

    # graphing
    p. graph -o test-outputs/test.$level.png  -d $level -C --cs e2etest.$level -m __TOTAL__ -m packet test.pcap

    # export minimal
    p. export -d $level -C --cs e2etest.$level -o test-outputs/test.$level.fsdb -c 10 -m IP  test.pcap

    # exprot everything
    p. export -d $level -C --cs e2etest.$level -o test-outputs/test.$level.fsdb test.pcap

done

# TBD: check failure cases (bad caches, etc)
