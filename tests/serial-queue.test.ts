import { describe, expect, it } from "vitest";
import { KeyedSerialQueue } from "../src/core/serial-queue.js";

describe("KeyedSerialQueue", () => {
  it("serializes the same route while allowing different routes", async () => {
    const queue = new KeyedSerialQueue();
    const events: string[] = [];
    let releaseFirst: (() => void) | undefined;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });

    const first = queue.run("route-a", async () => {
      events.push("a1-start");
      await firstGate;
      events.push("a1-end");
    });
    const second = queue.run("route-a", async () => {
      events.push("a2");
    });
    const other = queue.run("route-b", async () => {
      events.push("b");
    });

    await other;
    expect(events).toEqual(["a1-start", "b"]);
    releaseFirst?.();
    await Promise.all([first, second]);
    expect(events).toEqual(["a1-start", "b", "a1-end", "a2"]);
    expect(queue.activeKeys).toBe(0);
  });
});
