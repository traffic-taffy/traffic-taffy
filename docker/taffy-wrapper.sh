#!/bin/bash

usage() {
    echo "usage: TAFFY_SUBCOMMAND [ARGS]"
    echo "valid sub commands:"
    echo "  dissect"
    echo "  compare"
    echo "  graph"
    echo "  export"
    exit 1
}

# simply calls taffy with a prefix
case "$1" in
    dissect) ;;
    compare) ;;
    export) ;;
    graph) ;;
    -h) usage ;;
    *) echo "unknown sub command: $1" ; usage ;;
esac

taffy-"$@"
