import type { ImChannelAdapter } from "../core/contracts.js";
import { WeixinAdapter } from "../channels/weixin/adapter.js";
import { FetchWeixinProtocolClient } from "../channels/weixin/protocol.js";
import {
  loadOrCreateBearerToken,
  type GatewayPaths,
} from "./auth.js";
import { GatewayService } from "./gateway.js";
import { loadOrCreateMasterKey } from "./master-key.js";
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
  loadMasterKey?: (keyPath: string, databasePath: string) => Buffer;
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

function parsePositiveInteger(
    environment: NodeJS.ProcessEnv,
    name: string,
    fallback: number,
    maximum: number,
  ): number {
    const raw = environment[name];
    if (raw === undefined || raw.length === 0) {
      return fallback;
    }
    const value = Number(raw);
    if (!Number.isInteger(value) || value < 1 || value > maximum) {
      throw new Error(`${name} must be an integer from 1 to ${maximum}.`);
    }
    return value;
  }

export function lifecycleOptionsFromEnvironment(
    environment: NodeJS.ProcessEnv,
  ): Pick<
    GatewayStoreOptions,
    | "cleanupBatchSize"
    | "completedBodyRetentionHours"
    | "contextTokenRetentionDays"
    | "failedBodyRetentionHours"
  > {
    return {
      completedBodyRetentionHours: parsePositiveInteger(
        environment,
        "COPILOT_IM_GATEWAY_COMPLETED_BODY_HOURS",
        24,
        24 * 30,
      ),
      failedBodyRetentionHours: parsePositiveInteger(
        environment,
        "COPILOT_IM_GATEWAY_FAILED_BODY_HOURS",
        72,
        24 * 30,
      ),
      contextTokenRetentionDays: parsePositiveInteger(
        environment,
        "COPILOT_IM_GATEWAY_CONTEXT_TOKEN_DAYS",
        7,
        30,
      ),
      cleanupBatchSize: parsePositiveInteger(
        environment,
        "COPILOT_IM_GATEWAY_CLEANUP_BATCH_SIZE",
        500,
        5_000,
      ),
    };
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
    const environment = options.environment ?? process.env;
    const masterKey = (
      options.loadMasterKey ??
      ((keyPath, databasePath) =>
        loadOrCreateMasterKey({ keyPath, databasePath }))
    )(options.paths.keyPath, options.paths.databasePath);
    const bearerToken = (options.loadBearerToken ?? loadOrCreateBearerToken)(
      options.paths.tokenPath,
    );
    try {
      store = (options.createStore ?? ((databasePath, storeOptions) =>
        new GatewayStore(databasePath, storeOptions)))(
        options.paths.databasePath,
        {
          ...lifecycleOptionsFromEnvironment(environment),
          ...options.storeOptions,
          secretKey: masterKey,
        },
      );
    } finally {
      masterKey.fill(0);
    }
    service = new GatewayService(store);
    const channels = options.createChannels?.(store) ??
      productionChannels(store, environment);
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
