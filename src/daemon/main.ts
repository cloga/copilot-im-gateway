import { resolveGatewayPaths } from "./auth.js";
import {
  bootstrapGateway,
  parseGatewayPort,
} from "./startup.js";

const paths = resolveGatewayPaths();
const configuredPort = parseGatewayPort(process.env.COPILOT_IM_GATEWAY_PORT);
let stopPromise: Promise<void> | undefined;

function stop(signal: string): Promise<void> {
  stopPromise ??= (async () => {
    console.error(`Stopping gateway after ${signal}`);
    clearInterval(ownershipHeartbeat);
    await runtime.close();
  })();
  return stopPromise;
}

const runtime = await bootstrapGateway({
  port: configuredPort,
  paths,
  environment: process.env,
  onShutdown: () => stop("authenticated administrative request"),
});
const { running, store } = runtime;

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
