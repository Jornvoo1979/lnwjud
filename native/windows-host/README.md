# lnwjud Windows native host

This is the Windows implementation of lnwjud's existing integrity-bound native-host protocol.

M48 initially uses this executable only for internal safety primitives. It is an on-demand helper process, not a Windows Service, scheduler, watchdog, or persistent daemon.

Security constraints:

- no arbitrary shell or Git argv;
- no Windows-account creation;
- no NTFS ACL policy mutation;
- no Windows Security Policy mutation;
- no PowerShell `Add-Type`;
- no ExecutionPolicy changes or bypass;
- bounded NDJSON protocol;
- release-mode canonical path, byte-size and SHA-256 verification by the TypeScript bridge;
- filesystem identity uses native directory handles and NTFS file IDs;
- restricted-token and Job Object primitives fail closed when proof is unavailable.

Production worktree mutation remains disabled until the target-Windows acceptance matrix passes.
