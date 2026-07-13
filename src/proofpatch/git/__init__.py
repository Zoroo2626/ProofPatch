"""Controlled Git integration for independent repositories and exact patches."""

from proofpatch.git.client import GitClient
from proofpatch.git.clone import CloneKind, IndependentClone, create_independent_clone

__all__ = ["CloneKind", "GitClient", "IndependentClone", "create_independent_clone"]
