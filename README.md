# Identity Shield

Testing how well AWS CloudTrail detection rules hold up when the same attack is
performed in different ways.

This repository is at **M0**: the detection half of the pipeline, running entirely
on hand-written CloudTrail fixtures. No AWS access is required or used.

See `docs/plan.md` for the full design. The short version:

```
fixtures ──▶ parser ──▶ SQLite ──▶ rule engine ──▶ alerts ──▶ dashboard
                                    ▲
                                    ├── Python rules
                                    └── Sigma rules (pySigma backend)
```

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

python -m identity_shield.db.init
python -m identity_shield.detect.loader
python -m identity_shield.detect.replay --ruleset baseline-v1
pytest
streamlit run dashboard/app.py
```

## What each piece does

| Command | Purpose |
|---|---|
| `python -m identity_shield.db.init` | create/reset the SQLite schema |
| `python -m identity_shield.detect.loader` | load `fixtures/cloudtrail/**` into `event` |
| `python -m identity_shield.detect.replay --ruleset baseline-v1` | evaluate all rules against all events |
| `python -m identity_shield.detect.pysigma_backend --report` | Sigma conversion / compile-rate report |
| `pytest` | test suite |

## Design notes

- **Rules compile to predicates, not SQL.** Catalogue volume is small (tens of
  thousands of events), so evaluation is a Python scan over parsed dicts. SQLite
  is storage only.
- **Two rule paths.** Authored Python rules in `detect/python_rules.py`, and Sigma
  rules in `conf/rules/<ruleset>/`. Both produce `Rule` objects with the same
  evaluator, so they compete on identical inputs.
- **Fixtures are provisional.** They were written from AWS documentation, not
  captured from a live account, and must be replaced with real captures at M5.
