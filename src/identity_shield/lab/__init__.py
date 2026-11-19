"""Lab module: Terraform-managed AWS lab with a zero-residue teardown check."""

from identity_shield.lab.census import collect, compare, summarise
from identity_shield.lab.destroy import teardown
from identity_shield.lab.doctor import run_doctor

__all__ = ["collect", "compare", "run_doctor", "summarise", "teardown"]
