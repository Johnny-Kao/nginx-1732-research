# RESOLVER-SRV-FANOUT-001 — First dynamic validation

Status: **bounded fan-out confirmed; security impact unproven**  
Branch: `research/resolver-srv-fanout-001`  
NGINX version: **1.31.8** (compiled from this repository)  
Environment: Ubuntu 24.04 GitHub Actions, local-only DNS and HTTP servers  
Successful run: https://github.com/Johnny-Kao/nginx-1732-research/actions/runs/41520369222

## Question

Does a single SRV resolution create independent child CNAME chains, multiplying DNS work beyond the parent's per-context CNAME recursion limit?

## Harness

- Source: `research/resolver_srv_fanout.py`
- Workflow: `.github/workflows/resolver-srv-fanout.yml`
- A controlled UDP DNS server on `127.0.0.1` serves one SRV answer containing N distinct targets.
- Each target independently follows D CNAME records and then resolves one A record.
- NGINX has one worker, SRV-based upstream discovery, and IPv6 disabled.
- The local HTTP backend returns `backend-ok`; all five scenarios returned HTTP 200.
- Tests are intentionally bounded to at most 64 targets and 10 CNAME steps.

## Measurements

| Targets (N) | CNAME steps (D) | Expected A queries N×(D+1) | Observed A queries | Family RSS (KiB) | Median /health (ms) |
|---:|---:|---:|---:|---:|---:|
| 1 | 0 | 1 | 1 | 6212 | 0.277 |
| 8 | 0 | 8 | 8 | 6212 | 0.233 |
| 8 | 5 | 48 | 48 | 6364 | 0.235 |
| 32 | 5 | 192 | 192 | 6256 | 0.270 |
| 64 | 10 | 704 | 704 | 6420 | 0.245 |

Largest SRV DNS response: **2,539 bytes**, with no external DNS traffic.

## Interpretation and limitations

**Confirmed:** One SRV answer fans out into N independent address-resolution chains. The measured A query count follows N×(D+1), supporting the architectural resource-amplification observation.

**Not confirmed:** CPU exhaustion, high peak memory, a worker event-loop stall, exploitability by ordinary HTTP clients, or a DoS security vulnerability.

The family RSS and /health measurements were collected **after the DNS work completed**. They do **not** measure peak memory or concurrent request latency during active resolution. Results are from one CI run per scenario, without statistical uncertainty estimates, so differences of a few hundred KiB or fractions of a millisecond should not be interpreted as effects.

The initial run failed due to an incorrectly disabled NGINX rewrite module in the harness. The configuration was corrected, and the second CI run passed all five scenarios.

## Next research gate

Only escalate this into a security report if controlled follow-up work establishes a significant real-world resource impact, relevant attacker control over DNS discovery, or an independent lifetime/cancellation error. For the next gate, instrument peak worker RSS/CPU, health-check latency **during** delayed resolution, cancellation/timeout handling, and realistic deployment constraints. Avoid interpreting high DNS query counts alone as DoS.

No upstream change or PR has been made for this SRV investigation.
