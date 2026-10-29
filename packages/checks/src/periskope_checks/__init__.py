"""Importing the package registers every check."""
from periskope_checks import gitlab_checks, repo_checks, sonar_checks  # noqa: F401
from periskope_checks.registry import REGISTRY, run_all

__all__ = ["REGISTRY", "run_all"]
