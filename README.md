# ro-charging-fastpath

A Diameter Ro online charging engine (RFC 4006 credit control) written
twice, following the same rules:

- **baseline**: copies every AVP into a heap node, finds sessions and
  accounts by walking linked lists with `strcmp`, and builds each answer AVP
  by AVP in temporary buffers.
- **fast**: reads AVPs in place, keeps sessions and accounts in
  open-addressing hash tables (backward-shift deletion, no tombstones), takes
  sessions from a preallocated pool, and copies a pre-encoded template for the
  constant part of every answer. The hot path never calls `malloc`.

A differential test sends the same 200,000 CCRs through both engines,
including malformed ones, and requires **byte-identical CCAs and identical
final balances**. That's how the optimisations are shown not to change
behaviour.

> This is a clean-room re-implementation of the kind of work I did on IMS
> charging at C-DOT (restructuring data structures, removing redundant work
> and tightening interface messaging on the Ro path). It contains no C-DOT
> code, no CAP/SS7 stack, and none of its measurements. The numbers below come
> from this repository only.

## Build and run

```sh
make test       # rule tests + 200k-message differential test
make asan       # the same under AddressSanitizer + UBSan
make valgrind   # leak check
make bench      # ./charging-bench [messages]
```

## Results

2-vCPU cloud VM, gcc 13, `-O2`. The call mix is roughly one INITIAL and one
TERMINATION for every 3 UPDATEs, across a fixed number of concurrent sessions.
All requests are pre-built, so only the engine is timed.

| Active sessions | baseline msg/s | fast msg/s | ratio |
| --- | --- | --- | --- |
| 100 | 895,241 | 5,651,602 | 6.3x |
| 1,000 | 221,218 | 5,224,830 | 23.6x |
| 10,000 | 19,380 | 4,142,973 | 213.8x |

How to read this: the baseline's session lookup is O(n) in active sessions,
so the gap grows with load. The ratio depends mostly on that one choice.
Allocation and copying account for the ~6x left at small sizes. The baseline
is deliberately naive: it models first-version code, not a tuned competitor.

## Charging rules

See `src/engine.h` for the full list. In short: INITIAL reserves
`min(requested, balance)` up front. UPDATE and TERMINATION debit
`min(used, reserved)` and refund the rest, so over-reported usage can never
overdraw an account. A balance of zero gives `4012 CREDIT_LIMIT_REACHED`.
Unknown sessions give `5002`; unknown subscribers give `5030`.

## Layout

| File | What it does |
| --- | --- |
| `src/diam.c` | Header check, zero-copy AVP iterator with bounds checks, AVP writers, CCR builder |
| `src/baseline.c` | Linked lists, heap-copied AVPs, AVP-by-AVP answer assembly |
| `src/fast.c` | Hash tables, session pool, in-place parsing, templated answers |
| `tests/test_engine.c` | Rule tests for both engines + differential test with injected malformed messages |
| `src/bench.c` | Throughput benchmark at 100, 1k and 10k active sessions |

## Not done yet

- A network front end (TCP/SCTP, CER/CEA, DWR/DWA): the engine is fed buffers directly
- Volume-based units (octets) and rating groups (MSCC); only time units are modelled
- Multi-threading: the engine is single-threaded by design, shard by Session-Id to scale

MIT licensed.
