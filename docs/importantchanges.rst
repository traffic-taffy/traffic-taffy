Significant Version Changes
===========================

The following versions contained significant changes worthy of special
callout:

- 0.9
    - Massive code rewrite for various improvements
    - An entirely new `--config` flag for loading configuration from YAML
    - three algorithms for doing comparisons: `statistical`,
      `correlation`, and `correlationchanges` (see the `-A` flag).
    - A new `labels` extra processing module to split DNS names into pieces.

- 0.8.5
    - Added support for reporting a number of IANA numeric->name translations

- 0.8
    - Note that the -x switch to limit the list of results has been
      moved to -R.
    - Added ip2asn and psl (public suffix list) extra processing
      modules that can be enabled with a new -x switch.
    - Added a --merge command line option to merge all dissected
      traffic traces into a single time-stream.  For taffy-compare,
      this forces comparison by time bins across all supplied data.
    - All labeling switched to underbar separators rather that period
      separators to support future expression handling.

- 0.7
    - Support for comparing multiple files via time ranges rather than
      comparing file vs file.  Use --merge to enable this.

- 0.6
    - Support for parsing DNSTAP files
