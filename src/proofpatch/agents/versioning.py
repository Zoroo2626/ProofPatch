"""Strict parsing and minimum-version enforcement for provider CLI probes."""

import re

from proofpatch.errors import AgentError

VERSION = re.compile(r"(?<![0-9])(?P<version>[0-9]+\.[0-9]+\.[0-9]+)(?![0-9])")
MAXIMUM_VERSION_OUTPUT_BYTES = 4096


def parse_and_require_version(
    stdout: bytes,
    stderr: bytes,
    minimum: tuple[int, int, int],
) -> str:
    """Return a canonical semantic version or reject malformed/unsupported output."""

    if len(stdout) + len(stderr) > MAXIMUM_VERSION_OUTPUT_BYTES:
        raise AgentError("Agent CLI version output exceeded the safe limit")
    try:
        text = (stdout + b"\n" + stderr).decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise AgentError("Agent CLI version output was not valid UTF-8") from error
    if "\0" in text or any(ord(character) < 32 and character not in "\r\n\t" for character in text):
        raise AgentError("Agent CLI version output contained unsafe control characters")
    matches: list[str] = VERSION.findall(text)
    if len(matches) != 1:
        raise AgentError("Agent CLI version output did not contain exactly one semantic version")
    version = matches[0]
    parsed = tuple(int(part) for part in version.split("."))
    if parsed < minimum:
        required = ".".join(str(part) for part in minimum)
        raise AgentError(
            f"Agent CLI {version} is older than the minimum tested version {required}",
            remediation="Update the provider CLI in the configured immutable agent image.",
        )
    return version
