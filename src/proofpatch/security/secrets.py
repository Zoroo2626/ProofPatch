"""Exact-value redaction for controlled process logs and diagnostics."""

from dataclasses import dataclass

from proofpatch.errors import ConfigurationError

REDACTION_MARKER = b"[REDACTED_SECRET]"


@dataclass(frozen=True, slots=True)
class SecretRedactor:
    """Replace exact configured secret byte sequences, longest values first."""

    values: tuple[bytes, ...]

    @classmethod
    def from_values(cls, values: tuple[str, ...] | list[str]) -> "SecretRedactor":
        encoded: set[bytes] = set()
        for value in values:
            if not value:
                raise ConfigurationError("Secret values used for redaction must not be empty")
            try:
                raw = value.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ConfigurationError("Secret values must be valid Unicode text") from error
            encoded.add(raw)
        return cls(tuple(sorted(encoded, key=lambda item: (-len(item), item))))

    def redact(self, content: bytes) -> bytes:
        """Return content with every exact configured value replaced."""

        redacted = content
        for secret in self.values:
            redacted = redacted.replace(secret, REDACTION_MARKER)
        return redacted

    def contains_secret(self, content: str) -> bool:
        """Detect configured secrets in a command argument before process creation."""

        try:
            encoded = content.encode("utf-8")
        except UnicodeEncodeError:
            return True
        return any(secret in encoded for secret in self.values)
