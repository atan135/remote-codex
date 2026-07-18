export class OpsError extends Error {
  public constructor(
    public readonly code: string,
    public readonly path?: string
  ) {
    super(path === undefined ? code : `${code}:${path}`);
    this.name = "OpsError";
  }
}

export function fail(code: string, path?: string): never {
  throw new OpsError(code, path);
}
