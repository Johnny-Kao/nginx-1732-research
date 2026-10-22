# nginx #1732 isolated research

Source: nginx/nginx master at 140aa942711868a8daeb95810bc9a81f272ada72.
Work branch: research/issue-1732-early-hints. Master is an unchanged upstream mirror.

## Test
GitHub Actions `nginx-1732-research.yml` builds on Linux, executes a real 10,000-103 upstream smoke test, and runs the official nginx-tests proxy, upstream, proxy early hints and grpc early hints suites. **Only a completed green run is evidence of PASS**; skipped tests or an unrun workflow do not count.

The one-line patch aborts oversized hints via NGX_HTTP_UPSTREAM_INVALID_HEADER. Test failure logs and retry/compatibility findings must be reviewed before upstream PR or sign-off.
