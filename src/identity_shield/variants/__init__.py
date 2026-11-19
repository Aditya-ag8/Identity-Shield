"""Module 4 public surface."""

from identity_shield.variants.coverage import build_coverage, render_markdown, uncovered_pairs
from identity_shield.variants.generator import (
    GenerationOptions,
    GenerationResult,
    generate,
    generate_for_technique,
    select,
    summarise,
)
from identity_shield.variants.loader import (
    Catalogue,
    CatalogueError,
    Factor,
    Technique,
    load_catalogue,
)

__all__ = [
    "Catalogue",
    "CatalogueError",
    "Factor",
    "GenerationOptions",
    "GenerationResult",
    "Technique",
    "build_coverage",
    "generate",
    "generate_for_technique",
    "load_catalogue",
    "render_markdown",
    "select",
    "summarise",
    "uncovered_pairs",
]
