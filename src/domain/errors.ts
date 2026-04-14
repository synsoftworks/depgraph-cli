/** Raised when the caller supplies invalid input or unsupported usage. */
export class InvalidUsageError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'InvalidUsageError'
  }
}

/** Raised when registry or network-backed lookups fail. */
export class NetworkFailureError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'NetworkFailureError'
  }
}

/** Raised when local persistence or file access fails. */
export class StorageFailureError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'StorageFailureError'
  }
}
