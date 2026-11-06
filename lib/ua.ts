// What a user agent string says about the machine behind an account.
//
// Stealer logs and a fair number of ordinary breaches carry the browser string of the
// session that was captured. For a CSIRT that line is not metadata, it is the lead:
// "this account's last session came from a Windows 7 box running Chrome 49" says
// something about an estate that "LastLogin: 2021-11-02" never will, and two accounts
// sharing an unusual agent is a correlation worth drawing.
//
// PARSED, NOT MATCHED AGAINST A LIBRARY. The well-known parsers carry thousands of
// regexes and a release cadence, and the thing they buy you is coverage of devices
// nobody in a corporate breach is using. What matters here is a small number of facts
// read confidently, plus an honest "unknown" the rest of the time, because a wrong OS
// attribution in a case file is worse than a blank one.
//
// THE ORDER MATTERS AND IT IS NOT THE OBVIOUS ONE. Every Chromium browser claims to be
// Safari, and claims to be Mozilla before that; Edge claims to be Chrome; Opera claims
// to be both. So the checks run from the most specific token to the least, and the
// first match wins. Reversing any two of them silently reports every Edge session as
// Chrome, which is the kind of error that survives a review because the output still
// looks plausible.

export interface Agent {
  raw: string;
  os?: string;
  osVersion?: string;
  browser?: string;
  browserVersion?: string;
  device: "desktop" | "mobile" | "tablet" | "server" | "unknown";
  /** not a browser at all: a script, a library, a crawler, a headless run */
  automated?: boolean;
  /**
   * Things worth a second look, in the words a report would use.
   *
   * An end-of-life operating system or a browser years behind is exactly what an
   * infostealer finds on the machine it got onto, so the age of the agent is part of
   * the finding rather than trivia.
   */
  notes: string[];
}

const BOTS: { re: RegExp; name: string }[] = [
  { re: /python-requests|python-urllib|aiohttp/i, name: "Python HTTP client" },
  { re: /\bcurl\//i, name: "curl" },
  { re: /\bwget\b/i, name: "Wget" },
  { re: /Go-http-client/i, name: "Go HTTP client" },
  { re: /okhttp/i, name: "OkHttp" },
  { re: /java\/\d|Apache-HttpClient/i, name: "Java HTTP client" },
  { re: /axios|node-fetch|got\//i, name: "Node HTTP client" },
  { re: /PostmanRuntime|insomnia/i, name: "API client" },
  { re: /HeadlessChrome|PhantomJS|puppeteer|playwright|selenium|webdriver/i, name: "Headless browser" },
  { re: /bot\b|crawler|spider|slurp/i, name: "Crawler" },
];

/** Most specific first. Every one of these also claims to be something else. */
const BROWSERS: { re: RegExp; name: string }[] = [
  { re: /\bYaBrowser\/([\d.]+)/, name: "Yandex Browser" },
  { re: /\bOPR\/([\d.]+)/, name: "Opera" },
  { re: /\bOpera[ /]([\d.]+)/, name: "Opera" },
  { re: /\bEdg(?:e|A|iOS)?\/([\d.]+)/, name: "Edge" },
  { re: /\bSamsungBrowser\/([\d.]+)/, name: "Samsung Internet" },
  { re: /\bVivaldi\/([\d.]+)/, name: "Vivaldi" },
  { re: /\bCriOS\/([\d.]+)/, name: "Chrome" },
  { re: /\bFxiOS\/([\d.]+)/, name: "Firefox" },
  { re: /\bChrome\/([\d.]+)/, name: "Chrome" },
  { re: /\bFirefox\/([\d.]+)/, name: "Firefox" },
  { re: /\bMSIE ([\d.]+)|Trident\/.*rv:([\d.]+)/, name: "Internet Explorer" },
  { re: /\bVersion\/([\d.]+).*\bSafari\//, name: "Safari" },
];

const WIN_NT: Record<string, string> = {
  "10.0": "10 or 11", "6.3": "8.1", "6.2": "8", "6.1": "7", "6.0": "Vista", "5.1": "XP", "5.2": "XP",
};

/** Browser versions below this are years behind and worth saying so. */
const STALE: Record<string, number> = { Chrome: 100, Firefox: 100, Edge: 100, Opera: 85, Safari: 14 };

export function parseAgent(raw: string): Agent {
  const ua = String(raw ?? "").trim();
  const a: Agent = { raw: ua, device: "unknown", notes: [] };
  if (!ua) return a;

  for (const b of BOTS) {
    if (b.re.test(ua)) {
      a.browser = b.name;
      a.automated = true;
      a.device = "server";
      a.notes.push("Not a person at a browser: a script or an automated client.");
      return a;
    }
  }

  // ---- operating system ----
  let m: RegExpMatchArray | null;
  if ((m = ua.match(/Windows NT ([\d.]+)/))) {
    a.os = "Windows";
    a.osVersion = WIN_NT[m[1]] || m[1];
    a.device = "desktop";
    // 7, Vista and XP are all past end of support, and an unpatched desktop is the
    // machine an infostealer actually lands on
    if (["7", "Vista", "XP"].includes(a.osVersion)) a.notes.push(`Windows ${a.osVersion} is past end of support.`);
  } else if ((m = ua.match(/iPhone OS ([\d_]+)|CPU OS ([\d_]+)/))) {
    a.os = "iOS";
    a.osVersion = (m[1] || m[2]).replace(/_/g, ".");
    a.device = /iPad/.test(ua) ? "tablet" : "mobile";
  } else if ((m = ua.match(/Android ([\d.]+)/))) {
    a.os = "Android";
    a.osVersion = m[1];
    a.device = /Mobile/.test(ua) ? "mobile" : "tablet";
    if (Number(m[1].split(".")[0]) < 10) a.notes.push(`Android ${m[1]} no longer receives security updates.`);
  } else if ((m = ua.match(/Mac OS X ([\d_.]+)/))) {
    a.os = "macOS";
    a.osVersion = m[1].replace(/_/g, ".");
    a.device = /iPad|iPhone/.test(ua) ? "mobile" : "desktop";
  } else if (/Macintosh/.test(ua)) {
    a.os = "macOS"; a.device = "desktop";
  } else if (/CrOS/.test(ua)) {
    a.os = "ChromeOS"; a.device = "desktop";
  } else if (/Ubuntu|Debian|Fedora|CentOS|Red Hat/i.test(ua)) {
    a.os = (ua.match(/Ubuntu|Debian|Fedora|CentOS|Red Hat/i) || [""])[0];
    a.device = "desktop";
  } else if (/Linux/.test(ua)) {
    a.os = "Linux"; a.device = "desktop";
  } else if (/Windows Phone/.test(ua)) {
    a.os = "Windows Phone"; a.device = "mobile";
  }

  // ---- browser ----
  for (const b of BROWSERS) {
    const hit = ua.match(b.re);
    if (!hit) continue;
    a.browser = b.name;
    a.browserVersion = (hit[1] || hit[2] || "").split(".")[0] || undefined;
    break;
  }

  if (a.browser && a.browserVersion) {
    const cut = STALE[a.browser];
    const major = Number(a.browserVersion);
    if (cut && Number.isFinite(major) && major < cut) {
      a.notes.push(`${a.browser} ${major} is many versions behind; the session was not from a current install.`);
    }
  }
  if (!a.browser && !a.os) a.notes.push("Nothing recognisable: either a bespoke client or a mangled field.");
  return a;
}

/** One line, for a table cell. */
export function describeAgent(a: Agent): string {
  if (!a.raw) return "no agent";
  const os = a.os ? a.os + (a.osVersion ? " " + a.osVersion : "") : "unknown OS";
  const br = a.browser ? a.browser + (a.browserVersion ? " " + a.browserVersion : "") : "unknown client";
  return `${br} on ${os}`;
}

/**
 * The key two sessions share when they came from the same build.
 *
 * Deliberately coarse: the browser and its MAJOR version with the OS. Full version
 * strings differ between two sessions of one machine a week apart, so keying on them
 * would report a device as two devices, which is the failure that matters here.
 */
export function agentKey(a: Agent): string {
  if (!a.raw) return "";
  return [a.os || "?", a.osVersion || "", a.browser || "?", a.browserVersion || ""].join("|").toLowerCase();
}
