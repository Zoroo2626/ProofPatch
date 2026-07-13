"""Shared fail-closed validation for protected workflow configuration."""

from proofpatch.errors import ConfigurationError
from proofpatch.models.config import ProofPatchConfig


def validate_protected_configuration(config: ProofPatchConfig) -> None:
    """Reject every accepted field that protected mode cannot currently enforce."""

    if config.mode != "protected":
        raise ConfigurationError(
            "The full agent workflow requires protected mode",
            remediation="Use verify-patch for explicitly observation-only native verification.",
        )
    if config.setup.readonly_secret_files:
        raise ConfigurationError(
            "Protected workflows do not support setup secret-file mounts",
            remediation="Use agent environment allowlisting or remove readonly_secret_files.",
        )
    if config.runtime.dockerfile is not None or config.runtime.context != ".":
        raise ConfigurationError(
            "Protected workflows require a prebuilt immutable image; "
            "Dockerfile builds are unsupported"
        )
    if config.runtime.platform != "linux/amd64":
        raise ConfigurationError("Protected workflows currently support only linux/amd64 images")
    configured_tmpfs = tuple((item.path, item.size_mb, item.exec) for item in config.runtime.tmpfs)
    if configured_tmpfs not in {(), (("/tmp", 1024, False),)}:  # noqa: S108
        raise ConfigurationError("Protected workflows support only the default hardened /tmp tmpfs")
    if config.runtime.user != "1000:1000":
        raise ConfigurationError("Protected workflows support only user 1000:1000")
    if (
        config.verification.fail_on_test_deletion
        or config.verification.fail_on_skipped_test_addition
    ):
        raise ConfigurationError(
            "Configured test-deletion and skipped-test enforcement is not implemented"
        )
    if config.apply.branch_prefix != "proofpatch/" or config.apply.stage_changes:
        raise ConfigurationError(
            "Protected workflows currently require branch_prefix=proofpatch/ "
            "and stage_changes=false"
        )
