# Acceptance suites

Standalone, rerunnable drivers that exercise the platform end to end over REST against a **live
supervisor** (real Ghidra, real binary, no mocks). They are not part of the pytest run: `pytest`
covers `tests/unit` and `tests/integration` only, these scripts are launched directly and exit
non zero on any failure or probe mismatch.

Every suite shares one HTTP code path, `rest_client.py`, and writes evidence JSON under
`runtime/acceptance/api/`.

## Suites

| Suite | Covers |
| --- | --- |
| `infra` | health, mcp, program, project, task, analysis, transaction, memory and listing families, one real binary per run |
| `decomp_flow` | decomp, pcode, graph, search, reference and annotation families; writes live inside transaction begin to revert, plus expected rejection probes |
| `patch_load` | every patch op plus the gated ghidra family; mixed, concurrent and batch load soak across two workers |
| `reconstruction` | 84 reconstruction ops: function, variable, parameter, stackframe, type, layout, symbol, namespace, class, external, equate |

## Running

Start the supervisor first (see the main README), then point a suite at it:

```bash
python tests/acceptance/infra/test_infra.py \
  --base http://127.0.0.1:29950 --worker api_infra \
  --binary /path/to/binary --label mybin
```

Every script documents its own flags in its module docstring (`--soak`, `--stop-worker`,
`--out`, per phase evidence files, exit codes).
