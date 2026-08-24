import { loadOrCreateBearerToken, resolveGatewayPaths } from "./auth.js";
import { WeixinAdapter } from "../channels/weixin/adapter.js";
import { FetchWeixinProtocolClient } from "../channels/weixin/protocol.js";
import { GatewayService } from "./gateway.js";
import { startGatewayHttpServer } from "./http-server.js";
import { GatewayStore } from "./store.js";

const paths = resolveGatewayPaths();
const bearerToken = loadOrCreateBearerToken(paths.tokenPath);
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
const configuredPort = Number(process.env.COPILOT_IM_GATEWAY_PORT ?? 32147);
if (!Number.isInteger(configuredPort) || configuredPort < 0 || configuredPort > 65535) {
  throw new Error("COPILOT_IM_GATEWAY_PORT must be an integer from 0 to 65535.");
}

await service.startChannels();
const running = await startGatewayHttpServer({
  service,
  bearerToken,
  port: configuredPort,
});

console.error(`Copilot IM Gateway listening at ${running.url}`);
console.error(`Authentication token file: ${paths.tokenPath}`);

let stopping = false;
async function stop(signal: string): Promise<void> {
  if (stopping) {
    return;
  }
  stopping = true;
  console.error(`Stopping gateway after ${signal}`);
  await running.close();
  await service.stopChannels();
  store.close();
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
