"""Policy rules loader. The grading engine arrives in milestone 2."""

from __future__ import annotations

from importlib import resources
from typing import Any

import yaml


def load_rules() -> dict[str, Any]:
    text = resources.files(__package__).joinpath("rules.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text)
