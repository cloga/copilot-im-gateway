const regexSpecialCharacters = /[\\^$+?.()|[\]{}]/gu;

/** @param {string} value */
export function normalizePolicyPath(value) {
  return value.replaceAll("\\", "/").replace(/^\.\/+/u, "");
}

/**
 * Match repository paths with segment-aware `*`, `?`, and recursive `**`.
 *
 * @param {string} value
 * @param {string} pattern
 */
export function matchesGlob(value, pattern) {
  const path = normalizePolicyPath(value);
  const segments = normalizePolicyPath(pattern).split("/");
  let expression = "^";

  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index] ?? "";
    if (segment === "**") {
      expression += index === segments.length - 1 ? ".*" : "(?:[^/]+/)*";
      continue;
    }
    expression += segment
      .replace(regexSpecialCharacters, "\\$&")
      .replaceAll("*", "[^/]*")
      .replaceAll("?", "[^/]");
    if (index < segments.length - 1) {
      expression += "/";
    }
  }

  return new RegExp(`${expression}$`, "u").test(path);
}

/** @param {string} value @param {string[]} patterns */
export function matchesAny(value, patterns) {
  return patterns.some((pattern) => matchesGlob(value, pattern));
}

/**
 * @param {string} output
 * @returns {Array<{status: string, paths: string[]}>}
 */
export function parseNameStatus(output) {
  return output
    .split(/\r?\n/u)
    .filter(Boolean)
    .map((line) => {
      const fields = line.split("\t");
      const status = fields.shift();
      if (!status || fields.length === 0) {
        throw new Error(`Invalid git name-status entry: ${line}`);
      }
      const kind = status[0];
      const expectedPaths = kind === "R" || kind === "C" ? 2 : 1;
      if (fields.length !== expectedPaths) {
        throw new Error(`Invalid git name-status paths: ${line}`);
      }
      return {
        status,
        paths: fields.map(normalizePolicyPath),
      };
    });
}

/** @param {Array<{status: string, paths: string[]}>} changes */
export function changedPaths(changes) {
  return [...new Set(changes.flatMap((change) => change.paths))];
}
