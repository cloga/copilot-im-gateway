import { joinSession } from "@github/copilot-sdk/extension";
import { createAdminCanvas } from "./canvas.mjs";
import {
  createPermissionHandler,
  runInboundLoop,
} from "./extension-runtime.mjs";
import {
  GatewayClient,
  resolveGatewayConnection,
} from "./gateway-client.mjs";

const connection = resolveGatewayConnection();
const client = new GatewayClient(connection);
/** @type {{
 *   tenantId:string,
 *   channelId:string,
 *   accountId:string,
 *   conversationId:string,
 *   senderId:string,
 *   sessionId:string,
 *   workspaceAlias:string,
 *   workspaceRoot:string
 * } | undefined} */
let activeTurn;
/** @type {import("@github/copilot-sdk").CopilotSession | undefined} */
let session;
const stopController = new AbortController();
const onPermissionRequest = createPermissionHandler({
  client,
  getActiveTurn: () => activeTurn,
  signal: stopController.signal,
});

const canvas = createAdminCanvas({
  client,
  getSessionContext: () => {
    if (session === undefined) {
      throw new Error("Copilot session is not connected.");
    }
    return {
      sessionId: session.sessionId,
      workspacePath: process.cwd(),
    };
  },
});

const joinedSession = await joinSession({
  canvases: [canvas],
  onPermissionRequest,
});
session = joinedSession;
await client.ensureCompatible();

await joinedSession.log(
  `IM Gateway connected to ${connection.baseUrl}. Open the IM Gateway canvas to configure it.`,
);
joinedSession.on("session.shutdown", () => {
  stopController.abort();
});
void runInboundLoop({
  client,
  session: joinedSession,
  signal: stopController.signal,
  workspacePath: process.cwd(),
  setActiveTurn: (turn) => {
    activeTurn = turn;
  },
});
