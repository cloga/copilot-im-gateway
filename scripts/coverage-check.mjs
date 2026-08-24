import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

export const coverageMetrics = [
  "lines",
  "branches",
  "functions",
  "statements",
];

/**
 * @param {unknown} baselineValue
 * @param {unknown} summaryValue
 */
export function assertCoverageFloor(baselineValue, summaryValue) {
  const baseline = requireRecord(baselineValue, "coverage baseline");
  const summary = requireRecord(summaryValue, "coverage summary");
  const total = requireRecord(summary.total, "coverage summary total");
  /** @type {Record<string, number>} */
  const actual = {};

  for (const metric of coverageMetrics) {
    const expected = baseline[metric];
    const metricValue = requireRecord(total[metric], `coverage ${metric}`);
    const percentage = metricValue.pct;
    if (
      typeof expected !== "number" ||
      !Number.isFinite(expected) ||
      typeof percentage !== "number" ||
      !Number.isFinite(percentage)
    ) {
      throw new Error(`Coverage metric is missing or invalid: ${metric}`);
    }
    if (percentage < expected) {
      throw new Error(
        `Coverage ${metric} is ${percentage}, below protected baseline ${expected}`,
      );
    }
    actual[metric] = percentage;
  }

  return actual;
}

/**
 * @param {unknown} value
 * @param {string} label
 * @returns {Record<string, unknown>}
 */
function requireRecord(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} is invalid`);
  }
  return /** @type {Record<string, unknown>} */ (value);
}

async function main() {
  const [baselineValue, summary] = await Promise.all([
    readFile(".github/coverage-baseline.json", "utf8").then(JSON.parse),
    readFile("coverage/coverage-summary.json", "utf8").then(JSON.parse),
  ]);
  const baseline = requireRecord(baselineValue, "coverage baseline");
  const actual = assertCoverageFloor(baseline, summary);
  process.stdout.write(
    `Coverage meets protected baseline (${coverageMetrics
      .map((metric) => `${metric}=${actual[metric]}>=${baseline[metric]}`)
      .join(", ")}).\n`,
  );
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  await main();
}
