export class InvalidUsageError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'InvalidUsageError'
  }
}

export class NetworkFailureError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'NetworkFailureError'
  }
}

export class StorageFailureError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'StorageFailureError'
  }
}
