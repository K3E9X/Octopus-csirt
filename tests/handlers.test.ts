import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";

// A HANDLER ATTACHED BY REFERENCE IS CALLED WITH AN EVENT.
//
// `onClick={run}` hands React's click event to run() as its first argument. That is
// harmless while the function takes no parameters, and it stays harmless right up until
// somebody adds one. Then the event silently becomes that parameter.
//
// It happened here. A `fresh` flag was added to the search so a cached answer could be
// bypassed; the call site was `onClick={run}` and was not touched. The click event
// became `fresh`, went into JSON.stringify with the rest of the request body, and threw
// on the circular structure every DOM node has. The promise rejected with nobody
// listening, the fetch never ran, and the loading screen sat on its last animation line
// forever. Every search, for every account, until somebody opened the console.
//
// No type checker catches it: the parameter is optional and the handler's signature is
// compatible with a click handler's. So it is caught here, by reading the source,
// because the rule is about how a function is ATTACHED and not about what it is.

const FILES = readdirSync("components").filter((f) => f.endsWith(".tsx"));

/** on<Something>={identifier} — passed by reference rather than wrapped in an arrow. */
const BY_REFERENCE = /\bon[A-Z]\w*=\{(\w+)\}/g;

/** The declaration of that identifier, in any of the shapes this codebase uses. */
function paramsOf(src: string, name: string): string | null {
  const patterns = [
    new RegExp("const\\s+" + name + "\\s*=\\s*useCallback\\(\\s*(?:async\\s*)?\\(([^)]*)\\)"),
    new RegExp("const\\s+" + name + "\\s*=\\s*(?:async\\s*)?\\(([^)]*)\\)\\s*(?::[^=]*)?=>"),
    new RegExp("(?:async\\s+)?function\\s+" + name + "\\s*\\(([^)]*)\\)"),
  ];
  for (const re of patterns) {
    const m = src.match(re);
    if (m) return m[1].trim();
  }
  return null;
}

/** A parameter that is meant to receive the event, and therefore expects one. */
const EXPECTS_EVENT = /\b(e|ev|evt|event)\b|React\.\w*Event|MouseEvent|FormEvent|ChangeEvent/;

/** A parameter guarded against being handed one: typed unknown, or compared to a literal. */
const GUARDED = /:\s*unknown/;

test("no handler is attached by reference to a function that takes an argument", () => {
  const bad: string[] = [];
  for (const f of FILES) {
    const src = readFileSync("components/" + f, "utf8");
    for (const m of src.matchAll(BY_REFERENCE)) {
      const name = m[1];
      const params = paramsOf(src, name);
      if (params === null || params === "") continue;        // no parameters, nothing to hijack
      if (EXPECTS_EVENT.test(params)) continue;              // it is a real event handler
      if (GUARDED.test(params)) continue;                    // it refuses whatever it is given
      bad.push(`${f}: on…={${name}} but ${name}(${params})`);
    }
  }
  assert.deepEqual(
    bad, [],
    "Attached this way, React passes the click event as the first argument. Wrap it, " +
    "type the parameter `unknown` and compare against a literal, or take no parameters:\n  " + bad.join("\n  "),
  );
});
