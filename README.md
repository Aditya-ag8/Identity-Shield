# Identity Shield

Testing how well AWS CloudTrail detection rules hold up when the same attack is
performed in different ways.

Three parts are built: the offline detection core, the variant generator, and the
Terraform lab (create + zero-residue destroy). The attack runner and log
collector are not built, and no live AWS apply has been run yet. Details are in
the status section below.

See `docs/plan.md` for the full design. The short version:

```
fixtures ──▶ parser ──▶ SQLite ──▶ rule engine ──▶ alerts ──▶ dashboard
                                    ▲
                                    ├── Python rules
                                    └── Sigma rules (pySigma backend)

variants.jsonl ──▶ attack runner ──▶ CloudTrail ──▶ collector ──▶ replay
```

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

python -m identity_shield.db.init
python -m identity_shield.detect.loader
identity-shield replay --ruleset baseline-v1
identity-shield variants generate --db data/identity_shield.db
pytest
streamlit run dashboard/app.py
```

## Commands

| Command | Purpose |
|---|---|
| `identity-shield init` | create/reset the SQLite schema |
| `identity-shield load` | load `fixtures/cloudtrail/**` into `event` |
| `identity-shield replay --ruleset baseline-v1` | evaluate all rules against all events |
| `identity-shield compile` | Sigma conversion / compile-rate report |
| `identity-shield variants generate` | write `data/variants/variants.jsonl` + coverage |
| `identity-shield variants validate` | check a variants file against the catalogue |
| `identity-shield variants coverage` | recompute coverage from an existing file |
| `identity-shield lab doctor` | check Terraform, credentials and Organizations |
| `identity-shield lab up --yes` | `terraform init` + `apply` |
| `identity-shield lab down --yes` | `terraform destroy` + post-destroy census |
| `identity-shield lab down --check-only` | census and residue report without destroying |
| `identity-shield demo` | end-to-end offline demo |
| `pytest` | test suite |

`lab up` and `lab down` require `--yes`; `down` writes a teardown report to
`data/lab/` and exits non-zero if anything the lab owns survives.

## Status

| Check | Result |
|---|---|
| Tests | 139 passing (`pytest -q`) |
| Fixtures | 24 (8 techniques × catch / obvious / hard) |
| Round-1 rules | 8 Sigma + 5 Python |
| Fixture expectations | 24/24 met |
| pySigma compile rate, our corpus | 8/8 (100%) |
| pySigma compile rate, SigmaHQ AWS corpus | **56/58 (97%)** |
| Variants | 332 total: 8 baseline, 119 OFAT, 173 pairwise, 32 sealed holdout |
| Variant coverage | 159/159 levels, 80/80 factor pairs, 0 invalid variants |
| Terraform | `terraform validate` passes (AWS provider 5.100.0) |
| Live AWS apply/destroy | **not run** — no lab credentials configured |
| Lab census/teardown | tested against fake AWS clients, not a real account |

The two pySigma rules that do not compile both use the `fieldref` modifier
(`userIdentity.arn|fieldref`), which compares one field to another rather than
to a literal. That is a deliberate gap and belongs in the report as a
limitation, not a bug to chase.

## What is not built

- **Attack runner / executors.** `conf/techniques.yaml` names the Stratus
  techniques and boto3 entry points, but `src/identity_shield/runner/` does not
  exist. Techniques cannot be executed yet.
- **Log collector.** CloudTrail → S3 → SQS is provisioned, but nothing reads the
  queue into SQLite yet.
- **NAT A / NAT B runner network.** The variant factor `network_origin` includes
  `nat_a` and `nat_b`, and the plan defines them as two NAT gateways with fixed
  EIPs. The current Terraform creates the attack target (bucket, roles,
  instance) but not those egress paths. Until that exists, those two levels are
  generated but not executable.
- **Service-mediated and federated paths.** `service_mediated` needs a
  Lambda/ECS/CloudFormation invoker; `federated_session` can currently be
  approximated with `sts:GetFederationToken` but has no SSO/OIDC provider.
- **Preflight `SimulatePrincipalPolicy`.** The deny-list boundary is in place;
  the check that proves it does not block a technique runs in the runner.
- **Live verification.** Terraform is not on `PATH` in the dev environment, and
  no AWS credentials are configured. HCL syntax and provider schema are
  validated; apply/destroy behaviour is unverified.

## Contracts between parts

| Artefact | Produced by | Consumed by |
|---|---|---|
| `data/variants/variants.jsonl` | variant generator | attack runner, reporting |
| `variant` table | variant generator (`--db`) | attack runner |
| `inventory.json` | discovery | weakness mapping, runner |
| `findings.json` | weakness mapping | runner, report |
| `event` / `alert` tables | collector, detection | report, dashboard |
| `data/lab/teardown-report.json` | lab destroy | report, dashboard |

All artefact shapes live in `src/identity_shield/contracts.py`. There is one
hand-written validator per artefact; there are no separate JSON Schema files to
drift out of sync.

## Design notes

- **Rules compile to predicates, not SQL.** Catalogue volume is small (tens of
  thousands of events), so evaluation is a Python scan over parsed dicts. SQLite
  is storage only.
- **Two rule paths.** Authored Python rules in `detect/python_rules.py`, and Sigma
  rules in `conf/rules/<ruleset>/`. Both produce `Rule` objects with the same
  evaluator, so they compete on identical inputs.
- **Fixtures are provisional.** They were written from AWS documentation, not
  captured from a live account, and must be replaced with real captures when the
  runner exists.
- **Variants are deterministic.** Regenerating from the same catalogue produces
  the same ids, hashes and order. Deduplication is on the semantic hash, so a
  pairwise row that is really an OFAT row is dropped rather than counted twice.
- **The holdout is sealed.** Coverage numbers exclude it; analysis code reads
  `variants.jsonl` with `include_holdout=False` until the round-2 ruleset is
  frozen.
- **Teardown is proven, not assumed.** `lab down` takes a census before and
  after `terraform destroy` using read-only AWS calls, retries briefly, and
  fails the report if anything the lab owns remains or if the census itself
  could not run.
