import { loadOrCreateBearerToken, resolveGatewayPaths } from "./auth.js";
import { WeixinAdapter } from "../channels/weixin/adapter.js";
import { FetchWeixinProtocolClient } from "../channels/weixin/protocol.js";
import { GatewayService } from "./gateway.js";
import {
  startGatewayHttpServer,
  type RunningGatewayServer,
} from "./http-server.js";
import { GatewayStore } from "./store.js";

const paths = resolveGatewayPaths();
const bearerToken = loadOrCreateBearerToken(paths.tokenPath);
const configuredPort = Number(process.env.COPILOT_IM_GATEWAY_PORT ?? 32147);
if (!Number.isInteger(configuredPort) || configuredPort < 0 || configuredPort > 65535) {
  throw new Error("COPILOT_IM_GATEWAY_PORT must be an integer from 0 to 65535.");
}
const store = new GatewayStore(paths.databasePath);
const service = new GatewayService(store);
service.registerChannel(
  new WeixinAdapter({
    store,
    protocol: new FetchWeixinProtocolClient({
      loginBaseUrl:
        process.env.COPILOT_IM_GATEWAY_WEIXIN_BASE_URL ??
        "https://ilinkai.weixin.qq.com",
    }),
  }),
);
let channelsStarted = false;
let running: RunningGatewayServer;
try {
  await service.startChannels();
  channelsStarted = true;
  running = await startGatewayHttpServer({
    service,
    bearerToken,
    port: configuredPort,
  });
} catch (error) {
  if (channelsStarted) {
    await service.stopChannels();
  }
  store.close();
  throw error;
}

let nextCleanupAt = 0;
const ownershipHeartbeat = setInterval(() => {
  try {
    store.renewOwnership();
    if (Date.now() >= nextCleanupAt) {
      store.cleanup(new Date().toISOString());
      nextCleanupAt = Date.now() + 24 * 60 * 60 * 1_000;
    }
  } catch (error) {
    console.error("Gateway database ownership heartbeat failed", error);
    void stop("ownership-lost");
  }
}, 5_000);

console.error(`Copilot IM Gateway listening at ${running.url}`);
console.error(`Authentication token file: ${paths.tokenPath}`);

let stopping = false;
async function stop(signal: string): Promise<void> {
  if (stopping) {
    return;
  }
  stopping = true;
  console.error(`Stopping gateway after ${signal}`);
  clearInterval(ownershipHeartbeat);
  try {
    await running.close();
  } finally {
    try {
      await service.stopChannels();
    } finally {
      store.close();
    }
  }
}

process.once("SIGINT", () => {
  void stop("SIGINT").then(() => {
    process.exitCode = 0;
  });
});
process.once("SIGTERM", () => {
  void stop("SIGTERM").then(() => {
    process.exitCode = 0;
  });
});
