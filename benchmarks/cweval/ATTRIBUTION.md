# CWEval collection — attribution

Cases in this directory are derived from the **CWEval** benchmark.

- Source: https://github.com/Co1lin/CWEval
- Paper: https://arxiv.org/abs/2501.08200
- Vendored from commit: `8112fb410273`
- License: Apache-2.0 (see `LICENSE` in this directory).

## What we changed

Per CWEval task we generate a corpus case: the **insecure reference** is
placed under `source/` as the scan/fix target; CWEval's original task
(secure reference) and test oracle are copied **verbatim** under
`oracle/`. For Python, the vulnerable `source/` module is assembled from
the `*_unsafe` function embedded in CWEval's test (top-level imports + the
function + an alias to the canonical name); the oracle files are
unmodified. `meta.json` / `ground_truth.json` are ours.

The security/functional oracles assume a Linux/Docker environment (e.g.
they invoke `ls`, shell operators, `node`); run them via CWEval's
container, not natively on Windows.
