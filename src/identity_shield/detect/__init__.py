"""Detection package: parsing, rules, replay, and the pySigma backend."""

from identity_shield.detect.rules import Rule, load_sigma_file, load_sigma_text

__all__ = ["Rule", "load_sigma_file", "load_sigma_text"]
