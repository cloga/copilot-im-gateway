import type { ImChannelAdapter } from "../core/contracts.js";
import { WeixinAdapter } from "../channels/weixin/adapter.js";
import { FetchWeixinProtocolClient } from "../channels/weixin/protocol.js";
import {
  loadOrCreateBearerToken,
  type GatewayPaths,
} from "./auth.js";
import { GatewayService } from "./gateway.js";
import {
  reserveGatewayHttpServer,
  type RunningGatewayServer,
} from "./http-server.js";
import {
  GatewayStore,
  type GatewayStoreOptions,
} from "./store.js";

export interface GatewayRuntime {
  running: RunningGatewayServer;
  service: GatewayService;
  store: GatewayStore;
  close(): Promise<void>;
}

export interface GatewayBootstrapOptions {
  port: number;
  paths: GatewayPaths;
  environment?: NodeJS.ProcessEnv;
  storeOptions?: GatewayStoreOptions;
  onShutdown?: () => Promise<void> | void;
  loadBearerToken?: (tokenPath: string) => string;
  createStore?: (
    databasePath: string,
    options: GatewayStoreOptions,
  ) => GatewayStore;
  createChannels?: (store: GatewayStore) => readonly ImChannelAdapter[];
}

export function parseGatewayPort(value: string | undefined): number {
  const port = Number(value ?? 32147);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error("COPILOT_IM_GATEWAY_PORT must be an integer from 0 to 65535.");
  }
  return port;
}

function productionChannels(
  store: GatewayStore,
  environment: NodeJS.ProcessEnv,
): readonly ImChannelAdapter[] {
  return [
    new WeixinAdapter({
      store,
      protocol: new FetchWeixinProtocolClient({
        loginBaseUrl:
          environment.COPILOT_IM_GATEWAY_WEIXIN_BASE_URL ??
          "https://ilinkai.weixin.qq.com",
      }),
    }),
  ];
}

export async function bootstrapGateway(
  options: GatewayBootstrapOptions,
): Promise<GatewayRuntime> {
  const reservation = await reserveGatewayHttpServer(options.port);
  let store: GatewayStore | undefined;
  let service: GatewayService | undefined;
  try {
    const bearerToken = (options.loadBearerToken ?? loadOrCreateBearerToken)(
      options.paths.tokenPath,
    );
    store = (options.createStore ?? ((databasePath, storeOptions) =>
      new GatewayStore(databasePath, storeOptions)))(
      options.paths.databasePath,
      options.storeOptions ?? {},
    );
    service = new GatewayService(store);
    const channels = options.createChannels?.(store) ??
      productionChannels(store, options.environment ?? process.env);
    for (const channel of channels) {
      service.registerChannel(channel);
    }
    await service.startChannels();
    const running = reservation.activate({
      service,
      bearerToken,
      ...(options.onShutdown === undefined
        ? {}
        : { onShutdown: options.onShutdown }),
    });
    const activeService = service;
    const activeStore = store;
    let closePromise: Promise<void> | undefined;
    const close = (): Promise<void> => {
      closePromise ??= (async () => {
        const failures: unknown[] = [];
        try {
          await running.close();
        } catch (error) {
          failures.push(error);
        }
        try {
          await activeService.stopChannels();
        } catch (error) {
          failures.push(error);
        }
        try {
          activeStore.close();
        } catch (error) {
          failures.push(error);
        }
        if (failures.length > 0) {
          throw new AggregateError(failures, "Gateway shutdown failed.");
        }
      })();
      return closePromise;
    };
    return {
      running,
      service: activeService,
      store: activeStore,
      close,
    };
  } catch (error) {
    const failures: unknown[] = [error];
    try {
      await reservation.close();
    } catch (cleanupError) {
      failures.push(cleanupError);
    }
    if (service !== undefined) {
      try {
        await service.stopChannels();
      } catch (cleanupError) {
        failures.push(cleanupError);
      }
    }
    if (store !== undefined) {
      try {
        store.close();
      } catch (cleanupError) {
        failures.push(cleanupError);
      }
    }
    if (failures.length > 1) {
      throw new AggregateError(failures, "Gateway startup and cleanup failed.");
    }
    throw error;
  }
}
