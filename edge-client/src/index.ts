import { PROTOCOL_VERSION } from "@remote-codex/shared";
import type { EdgeClientConfig } from "@remote-codex/shared";

export {
  LOOPBACK_LISTEN_HOST,
  LoopbackConnectProxy,
  type EdgeStreamControl,
  type EdgeStreamEvent,
  type EdgeStreamEventListener,
  type EdgeStreamGateway,
  type LoopbackConnectProxyAddress,
  type LoopbackConnectProxyOptions
} from "./connect-proxy.js";

export const packageName = "@remote-codex/edge-client" as const;
export const sharedProtocolVersion: EdgeClientConfig["protocolVersion"] = PROTOCOL_VERSION;
