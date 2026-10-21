import type { Result } from '@lnwjud/domain';

export interface ManagedWriterAdmissionLease {
  readonly id: string;
  /** Release only when the mutation and all child processes are provably terminal. */
  releaseAfterVerifiedTermination(): Promise<void>;
}

export interface ManagedWriterAdmissionPort {
  enter(input: {
    readonly actorClientId: string;
    readonly workspaceId: string;
    readonly kind: 'synchronous_mutation' | 'uncontained_process' | 'contained_process';
    readonly nativeReceiptPath?: string;
    readonly nativeReceiptKind?: 'windows_job_v1' | 'windows_native_process_v1';
  }): Promise<Result<ManagedWriterAdmissionLease>>;
}
