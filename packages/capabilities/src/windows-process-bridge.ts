import { appError, err, type InvocationAuthorization, type Result } from '@lnwjud/domain';
import type { ProcessTreeTerminator } from '@lnwjud/process';
import { NativeHostProcessBridge, type NativeHostProtocolOptions, type NativeHostSpawner } from './native-host-protocol.js';

export interface WindowsProcessBridgeOptions {
  readonly executablePath: string;
  readonly expectedSha256?: string;
  readonly expectedSizeBytes?: number;
  readonly requireIntegrity?: boolean;
  readonly timeoutMs?: number;
  readonly maxPayloadBytes?: number;
  readonly terminator: ProcessTreeTerminator;
  readonly spawnProcess?: NativeHostSpawner;
}

/**
 * Integrity-bound NDJSON bridge for the packaged Windows native host.
 *
 * M48 initially uses this bridge only as an internal safety provider. Public
 * Windows capability routing remains on the existing provider until the native
 * host passes target-Windows acceptance.
 */
export class WindowsProcessBridge extends NativeHostProcessBridge {
  public constructor(options: WindowsProcessBridgeOptions) {
    const protocol: NativeHostProtocolOptions = { ...options, platform: 'win32' };
    super(protocol);
  }
}

export function unavailableWindowsHost(reason = 'native_host_missing'): Result<never> {
  return err(appError('PROCESS_NOT_FOUND', `Windows native host is unavailable (${reason})`, true));
}

export type WindowsNativeOperationAuthorization = InvocationAuthorization;
