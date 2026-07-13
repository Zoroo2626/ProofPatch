# Oracle Development

The Phase 3 command oracle is implemented.

Every future oracle must validate a structured specification, execute through the controlled
process layer, and return a common deterministic evaluation model. The first implementation will be
a command oracle using argument arrays, bounded output, explicit timeouts, and deterministic exit,
stdout, and stderr matchers.

An agent's narrative claim must never count as an oracle result.

Version 0.1 matchers support exact exit-code equality/inequality, stdout/stderr substring presence
or absence, and regex presence or absence. Regex patterns and inputs are size-limited and each
evaluation has an engine timeout. Required evaluations fail closed on process timeout,
cancellation, or truncated output.

Every new oracle type must implement the common validate/execute/evaluate interface, use the
controlled process layer where it launches a process, persist redacted log hashes rather than raw
output in events, and return the shared canonical evaluation model.
