"""Teardown and the zero-residue proof.

The sequence is deliberately:

    census -> terraform destroy -> wait -> census -> compare -> report

Terraform's exit code alone is not evidence. The second census is taken through
AWS APIs, so it catches three failures that a clean ``destroy`` can hide:

* resources created outside Terraform state (for example by an attack),
* a delete that returned success but did not take effect yet,
* a Terraform run that skipped a resource because its state was lost.

If the census itself fails (permission gap, throttling), the report is marked
failed. "We could not enumerate" is not the same as "nothing is there", and the
project's whole argument depends on not confusing the two.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from identity_shield import config
from identity_shield.contracts import TeardownReport, write_json, utc_now
from identity_shield.lab import census as census_module
from identity_shield.lab import provision
from identity_shield.lab.models import Residue


def teardown(
    session: Any,
    *,
    directory: str | Path | None = None,
    region: str | None = None,
    lab_name: str | None = None,
    report_path: str | Path | None = None,
    run_id: str | None = None,
    check_only: bool = False,
    attempts: int = 3,
    delay_seconds: float = 3.0,
    timeout: int = 1800,
) -> TeardownReport:
    started = utc_now()
    run_id = run_id or f"lab-{started.replace(':', '').replace('-', '')}"
    notes: list[str] = []

    before = census_module.collect(session, region=region, lab_name=lab_name)
    if before.errors:
        notes.append(
            f"pre-destroy census reported {len(before.errors)} error(s); "
            "the before/after comparison may be incomplete"
        )

    terraform_exit: int | None = None
    if check_only:
        after = before
        notes.append("check-only: terraform destroy was not run")
    else:
        result = provision.destroy(directory, timeout=timeout)
        terraform_exit = result.returncode
        if not result.ok:
            notes.append(f"terraform destroy exited {result.returncode}")
            tail = result.tail(10)
            if tail:
                notes.append(tail)

        after = census_module.collect(session, region=region, lab_name=lab_name)
        for _ in range(max(0, attempts - 1)):
            if not after.resources:
                break
            time.sleep(delay_seconds)
            after = census_module.collect(session, region=region, lab_name=lab_name)
            notes.append(f"re-census after {delay_seconds:.0f}s: {len(after.resources)} resource(s)")

    residue: Residue = census_module.compare(before, after)
    if after.errors:
        notes.append(
            f"post-destroy census reported {len(after.errors)} error(s); "
            "zero residue cannot be proven"
        )
    if residue.still_present:
        notes.append(f"{len(residue.still_present)} resource(s) survived teardown")

    passed = (
        not check_only
        and terraform_exit == 0
        and not residue.still_present
        and not after.errors
    )

    report = TeardownReport(
        run_id=run_id,
        started_at=started,
        finished_at=utc_now(),
        account_id=after.account_id or before.account_id,
        region=after.region or before.region,
        before=before.resources,
        after=after.resources,
        residue=residue.still_present,
        census_errors=after.errors,
        terraform_exit_code=terraform_exit,
        passed=passed,
        notes=tuple(notes),
    )

    if report_path:
        write_json(report_path, report.to_dict())
    return report


def default_report_path(run_id: str) -> Path:
    return config.LAB_DIR / f"teardown-{run_id}.json"
