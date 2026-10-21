# M48 P0 — Authenticated native terminal receipt design gate

Status: DESIGN ONLY / NOT IMPLEMENTED / NO-GO. This document does not authorize merging PR #2 or deploying its native receipt reader.

## Proven gap

`readWindowsContainmentReceipt` currently treats a schema-valid JSON object whose `specDigest` matches the expected value as a verified terminal receipt. A local writer that can alter the JSON can put in a matching digest, PID, jobIdentity, and Boolean flags. Host binary SHA-256 verification protects the selected executable, not receipt authorship. Comparing Native Host exit code with JSON is additional correlation but not an independent cryptographic or OS-authoritative attestation.

The deliberate RED test in `packages/process/src/windows-contained-launch.test.ts` proves this: matching digest + no trusted provenance is accepted.

## Required trust boundary (before implementation)

1. **Authority**: Identify which process is entitled to attest termination and which Windows identity/OS facility enforces that entitlement. The verifier MUST get its trusted root independently of receipt JSON and caller-controlled files. Do not put secret keys or a caller-chosen `trusted: true` in the spec or receipt.
2. **Authenticated transport**: Select a Windows-supported local IPC endpoint, such as an OS-protected named pipe with explicit owner, DACL, server/client PID verification and process-creation-time binding. Validate that these controls truly apply to the intended caller/user and cannot be substituted by another same-user process. Merely adding `GetNamedPipeClientProcessId` or a nonce is insufficient by itself.
3. **Invocation binding**: Every terminal event must bind canonical spec digest; unpredictable per-invocation challenge; Workspace ID, Goal ID, Task ID and Lease Generation from a verified host authority (never string fields supplied by an untrusted worker); the exact Native Host process instance; and a monotonic or one-time consumption record. Fail closed if these authorities cannot be verified.
4. **Windows evidence**: Native Host must report OS-backed restricted primary token state, assigned Job Object, child PID + creation time and zero active descendants. The current GUID `jobIdentity` is application-generated; it must not be misrepresented as kernel-backed job identity proof.
5. **Consumer enforcement**: Make ProcessManager's *verified terminal* callback and release of protected resources contingent upon successful independent authentication. Invalid, absent, expired, mismatched or replayed attestations produce `termination_unverified`. Ensure cancellation and normal close share the same gate.
6. **Lifecycle**: Document behavior for host/desktop crash, reboot, cancellation, timeout, retry, process PID reuse, stale receipt, spec replay, lost IPC and concurrent workers. Preserve durable state safely and never confuse an observed process exit with trusted goal/lease completion.

## Acceptance test matrix

| Case | Expected |
| --- | --- |
| Authorized signed/OS-attested terminal receipt for same exact invocation | Accept only after OS-backed positive verification |
| JSON forged with correct specDigest and all flags | Reject |
| Cross-task, cross-workspace, cross-goal, old lease generation | Reject |
| Duplicate/replayed terminal evidence | Reject |
| Native Host binary swapped after hash check | Reject or fail closed |
| Pipe/server impersonation and same-user local writer | Reject based on independently verifiable identity, not just matching nonce |
| PID reused, wrong creation time, wrong child Job | Reject |
| Active descendant remains, Job accounting fails | Do not acknowledge verified terminal state |
| Abrupt host death, missing evidence, truncated evidence | `termination_unverified` |
| Real Windows 10 x64 controlled tests, restart and real signed build | PASS before GO |
| Independent security review | Required before merge |

## Practical implementation sequence

- First document and independently review the Windows threat model, including whether Desktop and Native Host share a Windows token and whether Windows 10 Home can enforce the chosen IPC isolation.
- Implement the authentication authority and connection bootstrap with a genuine trusted Windows principal/process identity. Include attack tests *before* wiring the reader; keep the RED test active.
- Bind producer's OS observation to the exact authorized invocation, persist anti-replay evidence in a trusted control plane, and update every reader path (normal exit, timeout, cancel).
- Run Windows end-to-end native tests, test fork PR CI, then independent review and **target-host** acceptance. Keep PR Draft and NO-GO meanwhile.

## Non-solutions

A plain SHA-256 checksum, an HMAC key stored in the same user-writable directory, a self-signed key embedded within receipt JSON, PID alone, a random GUID, a boolean `osVerified`, or a passing mock test does not prove trust. No Windows policy changes, ACL bypass, new account, or production modifications are authorized by this design.
