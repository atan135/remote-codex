import type { Server as HttpsServer } from "node:https";

const TEST_PORT_MIN = 8_000;
const TEST_PORT_MAX = 9_000;
let nextCandidate = TEST_PORT_MIN + (process.pid % (TEST_PORT_MAX - TEST_PORT_MIN + 1));

/** 测试 listener 只在批准范围内逐端口原子尝试，绝不请求系统分配随机端口。 */
export async function listenOnApprovedTestPort(server: HttpsServer): Promise<number> {
  const candidateCount = TEST_PORT_MAX - TEST_PORT_MIN + 1;
  for (let attempt = 0; attempt < candidateCount; attempt += 1) {
    const port = nextCandidate;
    nextCandidate = port >= TEST_PORT_MAX ? TEST_PORT_MIN : port + 1;
    const listening = await new Promise<boolean>((resolve, reject) => {
      const handleListening = (): void => {
        server.off("error", handleError);
        resolve(true);
      };
      const handleError = (error: NodeJS.ErrnoException): void => {
        server.off("listening", handleListening);
        if (error.code === "EADDRINUSE" || error.code === "EACCES") {
          resolve(false);
          return;
        }
        reject(error);
      };
      server.once("listening", handleListening);
      server.once("error", handleError);
      server.listen(port, "127.0.0.1");
    });
    if (listening) {
      return port;
    }
  }
  throw new Error("SERVER_TEST_PORT_RANGE_EXHAUSTED");
}
