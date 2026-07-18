import type { Server as NetServer } from "node:net";

const TEST_PORT_MIN = 8_000;
const TEST_PORT_MAX = 9_000;
let nextCandidate = TEST_PORT_MIN + (process.pid % (TEST_PORT_MAX - TEST_PORT_MIN + 1));

export interface ApprovedTestPortResult<T> {
  readonly port: number;
  readonly value: T;
}

function nextApprovedCandidate(): number {
  const port = nextCandidate;
  nextCandidate = port >= TEST_PORT_MAX ? TEST_PORT_MIN : port + 1;
  return port;
}

/** 在批准范围内逐端口执行原子 listen callback，冲突时创建全新 listener 重试。 */
export async function startOnApprovedTestPort<T>(
  start: (port: number) => Promise<T>
): Promise<ApprovedTestPortResult<T>> {
  const candidateCount = TEST_PORT_MAX - TEST_PORT_MIN + 1;
  for (let attempt = 0; attempt < candidateCount; attempt += 1) {
    const port = nextApprovedCandidate();
    try {
      return { port, value: await start(port) };
    } catch (error: unknown) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "EADDRINUSE" && code !== "EACCES") {
        throw error;
      }
    }
  }
  throw new Error("SERVER_TEST_PORT_RANGE_EXHAUSTED");
}

/** 测试 listener 只在批准范围内逐端口原子尝试，绝不请求系统分配随机端口。 */
export async function listenOnApprovedTestPort(server: NetServer): Promise<number> {
  const started = await startOnApprovedTestPort(async (port) => {
    await new Promise<void>((resolve, reject) => {
      const handleListening = (): void => {
        server.off("error", handleError);
        resolve();
      };
      const handleError = (error: NodeJS.ErrnoException): void => {
        server.off("listening", handleListening);
        reject(error);
      };
      server.once("listening", handleListening);
      server.once("error", handleError);
      server.listen(port, "127.0.0.1");
    });
  });
  return started.port;
}
