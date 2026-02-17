export class NexusError extends Error {
  constructor(public code: string, message: string) {
    super(message);
    this.name = 'NexusError';
  }
}
