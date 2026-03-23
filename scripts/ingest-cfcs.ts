/**
 * CFCS Ingestion Crawler
 *
 * Scrapes the CFCS (Center for Cybersikkerhed / Styrelsen for Samfundssikkerhed)
 * website (cfcs.dk) and populates the SQLite database with guidance documents,
 * threat assessments (advisories), and framework metadata.
 *
 * Data sources:
 *   1. Guidance (vejledninger) — HTML pages + PDF links under
 *      cfcs.dk/da/forebyggelse/vejledninger/ and /nationale-anbefalinger/
 *   2. Threat assessments (trusselsvurderinger) — sector-specific PDFs and
 *      HTML pages under cfcs.dk/da/cybertruslen/trusselsvurderinger/
 *   3. Alerts (varsler) — cfcs.dk/da/handelser/varsler/
 *   4. Thematic articles — cfcs.dk/da/temasider/
 *
 * CFCS uses a server-rendered site (not SPA), so direct HTML scraping works.
 * PDF documents are fetched but only metadata is extracted (title, date from
 * filename/URL) — full PDF text extraction requires external tools.
 *
 * Usage:
 *   npx tsx scripts/ingest-cfcs.ts                   # full crawl
 *   npx tsx scripts/ingest-cfcs.ts --resume           # resume from checkpoint
 *   npx tsx scripts/ingest-cfcs.ts --dry-run          # log only, no DB writes
 *   npx tsx scripts/ingest-cfcs.ts --force            # drop and recreate DB
 *   npx tsx scripts/ingest-cfcs.ts --advisories-only  # only threat assessments + alerts
 *   npx tsx scripts/ingest-cfcs.ts --guidance-only    # only guidance documents
 */

import Database from "better-sqlite3";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import * as cheerio from "cheerio";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DB_PATH = process.env["CFCS_DB_PATH"] ?? "data/cfcs.db";
const STATE_FILE = resolve(dirname(DB_PATH), ".ingest-state.json");
const RATE_LIMIT_MS = 1500;
const MAX_RETRIES = 3;
const RETRY_BACKOFF_MS = 3000;
const REQUEST_TIMEOUT_MS = 30_000;
const USER_AGENT =
  "ansvar-cfcs-mcp-crawler/1.0 (contact: hello@ansvar.ai; compliance research)";

const CFCS_BASE = "https://www.cfcs.dk";

// ---------------------------------------------------------------------------
// Known content URLs
// ---------------------------------------------------------------------------

// Guidance publications (vejledninger) — curated list of known pages.
// CFCS publishes guidance as HTML pages and downloadable PDFs.
const GUIDANCE_URLS: string[] = [
  // Core guidance documents
  "/da/forebyggelse/vejledninger/rejser/",
  "/da/forebyggelse/vejledninger/handbog-i-sikkerhed-for-mobile-enheder/",
  "/da/forebyggelse/vejledninger/kom-i-gang-med-at-beskytte-iot/",
  "/da/forebyggelse/vejledninger/distancearbejde/opdater-sikkerhedspolitikkerne/",
  "/da/forebyggelse/vejledninger/vejledning-metode-til-at-arbejde-med-adfardsindsatser/",
  // Nationale anbefalinger (national recommendations)
  "/da/forebyggelse/nationale-anbefalinger/",
  "/da/forebyggelse/nationale-anbefalinger/logning/",
  "/da/forebyggelse/nationale-anbefalinger/logning/e-mail-logning/",
  // Password security
  "/en/forebyggelse/guidance/passwords/",
  // Thematic pages with substantive cybersecurity content
  "/da/temasider/",
];

// Known guidance PDFs (direct PDF URLs for metadata extraction)
const GUIDANCE_PDF_URLS: string[] = [
  "/globalassets/cfcs/dokumenter/vejledninger/-cyberforsvar-der-virker-2023-.pdf",
  "/globalassets/cfcs/dokumenter/vejledninger/-passwordsikkerhed-oktober-2023-.pdf",
  "/globalassets/cfcs/dokumenter/vejledninger/cfcs-phishingvejledning-2022.pdf",
  "/globalassets/cfcs/dokumenter/vejledninger/cfcs-vejledning-beskyt-iot-enheder.pdf",
  "/globalassets/cfcs/dokumenter/vejledninger/-cybersikkerhed-i-overvagningsudstyr-.pdf",
  "/globalassets/cfcs/dokumenter/vejledninger/cybersikkerhed-for-bestyrelser.pdf",
  "/globalassets/cfcs/dokumenter/vejledninger/cybersikkerhed-pa-rejsen-organisationen.pdf",
];

// Threat assessment pages (trusselsvurderinger) — both HTML landing pages and PDFs
const THREAT_ASSESSMENT_URLS: string[] = [
  // Main overview
  "/da/cybertruslen/trusselsvurderinger/",
  // Sector-specific HTML pages
  "/da/cybertruslen/trusselsvurderinger/cybertruslen-mod-danmark/",
  "/da/cybertruslen/trusselsvurderinger/finans/",
  "/da/cybertruslen/trusselsvurderinger/soefart/",
  "/da/cybertruslen/trusselsvurderinger/transport/",
  "/da/cybertruslen/trusselsvurderinger/forsvarsindustrien/",
  "/da/cybertruslen/trusselsvurderinger/tele/",
  "/da/cybertruslen/trusselsvurderinger/trusselsvurdering-cybertruslen-mod-gronland/",
  "/da/cybertruslen/trusselsvurderinger/cfcs-haver-trusselsniveauet-for-cyberaktivisme/",
];

// Threat assessment PDFs
const THREAT_PDF_URLS: string[] = [
  "/globalassets/cfcs/dokumenter/trusselsvurderinger/cfcs---cybertruslen-mod-danmark-2024.pdf",
  "/globalassets/cfcs/dokumenter/trusselsvurderinger/CFCS-cybertruslen-mod-vandsektoren-2025.pdf",
  "/globalassets/cfcs/dokumenter/trusselsvurderinger/-cybertruslen-mod-telesektoren-2025-.pdf",
  "/globalassets/cfcs/dokumenter/trusselsvurderinger/samsik---cybertruslen-mod-rumsektoren-2025.pdf",
  "/globalassets/cfcs/dokumenter/trusselsvurderinger/-trusselsvurdering_cybertruslen-mod-sundhedssektoren_2024-.pdf",
  "/globalassets/cfcs/dokumenter/trusselsvurderinger/cybertruslen-mod-forskning-og-universiteter.pdf",
];

// Alerts page (varsler)
const ALERTS_INDEX_URL = "/da/handelser/varsler/";

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const resume = args.includes("--resume");
const force = args.includes("--force");
const advisoriesOnly = args.includes("--advisories-only");
const guidanceOnly = args.includes("--guidance-only");

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function log(msg: string): void {
  const ts = new Date().toISOString().slice(0, 19);
  console.log(`[${ts}] ${msg}`);
}

function warn(msg: string): void {
  const ts = new Date().toISOString().slice(0, 19);
  console.warn(`[${ts}] WARN: ${msg}`);
}

function logError(msg: string): void {
  const ts = new Date().toISOString().slice(0, 19);
  console.error(`[${ts}] ERROR: ${msg}`);
}

// ---------------------------------------------------------------------------
// State persistence (for --resume)
// ---------------------------------------------------------------------------

interface IngestState {
  guidanceCompleted: string[];
  advisoriesCompleted: string[];
  alertsCompleted: string[];
  lastRun: string;
}

function loadState(): IngestState {
  if (resume && existsSync(STATE_FILE)) {
    try {
      const raw = readFileSync(STATE_FILE, "utf-8");
      const s = JSON.parse(raw) as IngestState;
      log(
        `Resuming from checkpoint (${s.lastRun}): ` +
          `${s.guidanceCompleted.length} guidance, ` +
          `${s.advisoriesCompleted.length} threat assessments, ` +
          `${s.alertsCompleted.length} alerts`,
      );
      return s;
    } catch {
      warn("Could not parse state file, starting fresh");
    }
  }
  return {
    guidanceCompleted: [],
    advisoriesCompleted: [],
    alertsCompleted: [],
    lastRun: "",
  };
}

function saveState(state: IngestState): void {
  state.lastRun = new Date().toISOString();
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

let lastRequestTime = 0;

async function rateLimitedFetch(
  url: string,
  retries = MAX_RETRIES,
): Promise<Response> {
  const now = Date.now();
  const elapsed = now - lastRequestTime;
  if (elapsed < RATE_LIMIT_MS) {
    await sleep(RATE_LIMIT_MS - elapsed);
  }
  lastRequestTime = Date.now();

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const resp = await fetch(url, {
        signal: controller.signal,
        headers: {
          "User-Agent": USER_AGENT,
          Accept:
            "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8",
          "Accept-Language": "da-DK, da;q=0.9, en;q=0.5",
        },
        redirect: "follow",
      });

      clearTimeout(timeout);

      if (resp.status === 429) {
        const retryAfter = parseInt(
          resp.headers.get("Retry-After") ?? "10",
          10,
        );
        warn(`Rate limited (429) on ${url}, waiting ${retryAfter}s`);
        await sleep(retryAfter * 1000);
        continue;
      }

      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
      }

      return resp;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (attempt < retries) {
        const backoff = RETRY_BACKOFF_MS * attempt;
        warn(
          `Attempt ${attempt}/${retries} failed for ${url}: ${msg}. Retrying in ${backoff}ms...`,
        );
        await sleep(backoff);
      } else {
        throw new Error(`All ${retries} attempts failed for ${url}: ${msg}`);
      }
    }
  }

  throw new Error(`Fetch failed for ${url}`);
}

async function fetchHtml(url: string): Promise<string> {
  const resp = await rateLimitedFetch(url);
  return resp.text();
}

/**
 * Fetch a PDF and return its byte length. We record the PDF as a guidance
 * entry with metadata extracted from the URL/filename. Full text extraction
 * from PDFs requires external tooling (pdftotext, etc.) and is out of scope
 * for this crawler — the full_text field will contain a note about the PDF.
 */
async function fetchPdfMetadata(
  url: string,
): Promise<{ ok: boolean; size: number }> {
  try {
    const resp = await rateLimitedFetch(url);
    const buf = await resp.arrayBuffer();
    return { ok: true, size: buf.byteLength };
  } catch {
    return { ok: false, size: 0 };
  }
}

// ---------------------------------------------------------------------------
// HTML parsing helpers
// ---------------------------------------------------------------------------

/**
 * Extract the main content area from a CFCS page. The site uses Episerver
 * CMS with a main content container. We target the article/main elements.
 */
function extractMainContent(html: string): string {
  const $ = cheerio.load(html);

  // Remove navigation, footer, scripts, styles
  $("nav, footer, script, style, header, .cookie-banner, .breadcrumb").remove();

  // Try common content selectors used by cfcs.dk (Episerver CMS)
  const selectors = [
    "main .page-content",
    "main article",
    "main .content-area",
    ".article-content",
    "main",
    "article",
    "#content",
    ".content",
  ];

  for (const sel of selectors) {
    const el = $(sel);
    if (el.length > 0) {
      const text = el.text().replace(/\s+/g, " ").trim();
      if (text.length > 100) {
        return text;
      }
    }
  }

  // Fallback: entire body text
  const bodyText = $("body").text().replace(/\s+/g, " ").trim();
  return bodyText;
}

/**
 * Extract the page title from a CFCS page.
 */
function extractTitle(html: string): string {
  const $ = cheerio.load(html);

  // Try h1 first, then og:title, then <title>
  const h1 = $("h1").first().text().trim();
  if (h1.length > 3) return h1;

  const ogTitle = $('meta[property="og:title"]').attr("content")?.trim();
  if (ogTitle && ogTitle.length > 3) return ogTitle;

  const titleTag = $("title").text().trim();
  // Strip " | Styrelsen for Samfundssikkerhed" or " | CFCS" suffix
  return titleTag
    .replace(/\s*\|.*$/, "")
    .trim();
}

/**
 * Extract the publication date from a CFCS page. Dates appear in various
 * formats: "Oktober 2023", "Januar 2025", "2024-09-15", etc.
 */
function extractDate(html: string): string | null {
  const $ = cheerio.load(html);

  // Look for date in structured metadata
  const datePublished =
    $('meta[name="date"]').attr("content") ??
    $('meta[property="article:published_time"]').attr("content") ??
    $('meta[name="dcterms.date"]').attr("content") ??
    $('meta[name="DC.date"]').attr("content");

  if (datePublished) {
    const d = datePublished.slice(0, 10);
    if (/^\d{4}-\d{2}-\d{2}$/.test(d)) return d;
  }

  // Search for common date patterns in the page text
  const bodyText = $("body").text();

  // "YYYY-MM-DD"
  const isoMatch = /(\d{4}-\d{2}-\d{2})/.exec(bodyText);
  if (isoMatch?.[1]) return isoMatch[1];

  // Danish month names: "Januar 2025", "Marts 2024", etc.
  const danishMonths: Record<string, string> = {
    januar: "01",
    februar: "02",
    marts: "03",
    april: "04",
    maj: "05",
    juni: "06",
    juli: "07",
    august: "08",
    september: "09",
    oktober: "10",
    november: "11",
    december: "12",
  };

  const monthPattern =
    /(\d{1,2})\.?\s*(januar|februar|marts|april|maj|juni|juli|august|september|oktober|november|december)\s*(\d{4})/i;
  const dayMonthYear = monthPattern.exec(bodyText);
  if (dayMonthYear?.[1] && dayMonthYear[2] && dayMonthYear[3]) {
    const month = danishMonths[dayMonthYear[2].toLowerCase()];
    if (month) {
      return `${dayMonthYear[3]}-${month}-${dayMonthYear[1].padStart(2, "0")}`;
    }
  }

  // "Måned YYYY" without day
  const monthYearPattern =
    /(januar|februar|marts|april|maj|juni|juli|august|september|oktober|november|december)\s+(\d{4})/i;
  const monthYear = monthYearPattern.exec(bodyText);
  if (monthYear?.[1] && monthYear[2]) {
    const month = danishMonths[monthYear[1].toLowerCase()];
    if (month) {
      return `${monthYear[2]}-${month}-01`;
    }
  }

  return null;
}

/**
 * Extract a summary from the page. Uses og:description, meta description,
 * or the first substantial paragraph.
 */
function extractSummary(html: string): string | null {
  const $ = cheerio.load(html);

  const ogDesc = $('meta[property="og:description"]').attr("content")?.trim();
  if (ogDesc && ogDesc.length > 20) return ogDesc;

  const metaDesc = $('meta[name="description"]').attr("content")?.trim();
  if (metaDesc && metaDesc.length > 20) return metaDesc;

  // First paragraph with meaningful length
  const paragraphs = $("main p, article p, .content p");
  for (let i = 0; i < paragraphs.length; i++) {
    const text = $(paragraphs[i]).text().trim();
    if (text.length > 50) {
      return text.length > 500 ? text.slice(0, 497) + "..." : text;
    }
  }

  return null;
}

/**
 * Extract links from a CFCS listing page. Returns hrefs matching a pattern.
 */
function extractLinks(
  html: string,
  hrefPattern?: RegExp,
): Array<{ href: string; text: string }> {
  const $ = cheerio.load(html);
  const results: Array<{ href: string; text: string }> = [];

  $("a[href]").each((_i, el) => {
    const href = $(el).attr("href") ?? "";
    const text = $(el).text().trim();
    if (href && text && (!hrefPattern || hrefPattern.test(href))) {
      // Normalise relative URLs
      const fullHref = href.startsWith("http")
        ? href
        : href.startsWith("/")
          ? href
          : `/${href}`;
      results.push({ href: fullHref, text });
    }
  });

  return results;
}

/**
 * Generate a reference ID from a URL path.
 * "/da/forebyggelse/vejledninger/rejser/" -> "CFCS-VEJ-rejser"
 */
function urlToReference(urlPath: string, prefix: string): string {
  const slug = urlPath
    .replace(/^\/da\//, "")
    .replace(/^\/en\//, "")
    .replace(/\/$/, "")
    .replace(/\//g, "-")
    .replace(/[^a-z0-9-]/gi, "")
    .toLowerCase();

  // Truncate if too long
  const shortSlug = slug.length > 60 ? slug.slice(0, 60) : slug;
  return `${prefix}-${shortSlug}`;
}

/**
 * Generate a reference ID from a PDF filename.
 * "cfcs-phishingvejledning-2022.pdf" -> "CFCS-PDF-cfcs-phishingvejledning-2022"
 */
function pdfUrlToReference(url: string, prefix: string): string {
  const filename = url.split("/").pop() ?? "unknown";
  const slug = filename
    .replace(/\.pdf$/i, "")
    .replace(/[^a-z0-9-]/gi, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .toLowerCase();

  const shortSlug = slug.length > 60 ? slug.slice(0, 60) : slug;
  return `${prefix}-${shortSlug}`;
}

/**
 * Attempt to extract a year from a PDF URL for date approximation.
 */
function extractYearFromUrl(url: string): string | null {
  const match = /(\d{4})/.exec(url.split("/").pop() ?? "");
  if (match?.[1]) {
    const year = parseInt(match[1], 10);
    if (year >= 2015 && year <= 2030) {
      return `${year}-01-01`;
    }
  }
  return null;
}

/**
 * Classify guidance type from URL or title.
 */
function classifyGuidanceType(url: string, title: string): string {
  const lower = (url + " " + title).toLowerCase();
  if (lower.includes("anbefaling")) return "recommendation";
  if (lower.includes("vejledning") || lower.includes("guidance"))
    return "guidance";
  if (lower.includes("handbog") || lower.includes("handbook")) return "handbook";
  if (lower.includes("rapport") || lower.includes("report")) return "report";
  if (lower.includes("standard") || lower.includes("nis2")) return "standard";
  if (lower.includes("tema")) return "thematic";
  return "guidance";
}

/**
 * Classify guidance series from URL.
 */
function classifyGuidanceSeries(url: string): string {
  if (url.includes("nationale-anbefalinger")) return "Nationale Anbefalinger";
  if (url.includes("vejledninger")) return "CFCS Vejledninger";
  if (url.includes("temasider")) return "Temasider";
  if (url.includes("forebyggelse")) return "Forebyggelse";
  return "CFCS";
}

/**
 * Determine threat level / severity from Danish threat assessment text.
 * CFCS uses: MEGET HØJ, HØJ, MIDDEL, LAV, INGEN
 */
function classifyThreatSeverity(text: string): string {
  const lower = text.toLowerCase();
  if (lower.includes("meget høj") || lower.includes("meget hoj"))
    return "critical";
  if (
    lower.includes("høj") ||
    lower.includes("hoj") ||
    lower.includes("high")
  )
    return "high";
  if (
    lower.includes("middel") ||
    lower.includes("medium") ||
    lower.includes("moderat")
  )
    return "medium";
  if (lower.includes("lav") || lower.includes("low")) return "low";
  return "medium";
}

/**
 * Extract topics from text as a JSON array of keyword strings.
 */
function extractTopics(text: string, title: string): string {
  const topics: string[] = [];
  const combined = (title + " " + text).toLowerCase();

  const topicKeywords: Array<[string, string]> = [
    ["ransomware", "ransomware"],
    ["phishing", "phishing"],
    ["ddos", "DDoS"],
    ["nis2", "NIS2"],
    ["nis 2", "NIS2"],
    ["iot", "IoT"],
    ["ot-", "OT"],
    ["ics", "ICS"],
    ["scada", "SCADA"],
    ["leverandørkæde", "leverandorkaede"],
    ["leverandorkæde", "leverandorkaede"],
    ["supply chain", "leverandorkaede"],
    ["kryptografi", "kryptografi"],
    ["kryptering", "kryptering"],
    ["password", "adgangskoder"],
    ["adgangskode", "adgangskoder"],
    ["logning", "logning"],
    ["cloud", "cloud"],
    ["cyberspionage", "cyberspionage"],
    ["hacktivisme", "hacktivisme"],
    ["cyberkriminalitet", "cyberkriminalitet"],
    ["kritisk infrastruktur", "kritisk-infrastruktur"],
    ["trusselsvurdering", "trusselsvurdering"],
    ["cyberforsvar", "cyberforsvar"],
    ["mobile enheder", "mobile-enheder"],
    ["rejse", "rejsesikkerhed"],
    ["distancearbejde", "distancearbejde"],
    ["hjemmearbejde", "distancearbejde"],
    ["e-mail", "emailsikkerhed"],
    ["email", "emailsikkerhed"],
    ["mfa", "MFA"],
    ["multifaktor", "MFA"],
    ["patching", "patching"],
    ["sårbarhed", "sarbarheder"],
    ["sarbarhed", "sarbarheder"],
    ["hændelsesrespons", "haendelsesrespons"],
    ["haendelsesrespons", "haendelsesrespons"],
    ["incident", "haendelsesrespons"],
    ["backup", "backup"],
    ["sikkerhedskopiering", "backup"],
    ["segmentering", "netvaerkssegmentering"],
    ["energi", "energi"],
    ["finans", "finans"],
    ["sundhed", "sundhed"],
    ["transport", "transport"],
    ["søfart", "soefart"],
    ["soefart", "soefart"],
    ["tele", "tele"],
    ["forsvar", "forsvar"],
    ["rum", "rumsektoren"],
    ["vand", "vandsektoren"],
    ["universitet", "universiteter"],
  ];

  for (const [keyword, topic] of topicKeywords) {
    if (combined.includes(keyword) && !topics.includes(topic)) {
      topics.push(topic);
    }
  }

  return JSON.stringify(topics.slice(0, 15));
}

/**
 * Extract CVE references from text.
 */
function extractCves(text: string): string[] {
  const cvePattern = /CVE-\d{4}-\d{4,}/g;
  const matches = text.match(cvePattern);
  if (!matches) return [];
  return [...new Set(matches)];
}

/**
 * Extract affected products from alert text.
 */
function extractAffectedProducts(text: string, title: string): string[] {
  const products: string[] = [];
  const combined = title + " " + text;

  // Common product patterns in CFCS alerts
  const productPatterns: Array<[RegExp, string]> = [
    [/\bCisco\b/i, "Cisco"],
    [/\bMicrosoft\b/i, "Microsoft"],
    [/\bJetBrains\b/i, "JetBrains"],
    [/\bTeamCity\b/i, "JetBrains TeamCity"],
    [/\bFortinet\b/i, "Fortinet"],
    [/\bPalo Alto\b/i, "Palo Alto Networks"],
    [/\bVMware\b/i, "VMware"],
    [/\bCitrix\b/i, "Citrix"],
    [/\bApache\b/i, "Apache"],
    [/\bIvanti\b/i, "Ivanti"],
    [/\bSolarWinds\b/i, "SolarWinds"],
    [/\bExchange\b/i, "Microsoft Exchange"],
    [/\bWindows\b/i, "Microsoft Windows"],
    [/\bLinux\b/i, "Linux"],
    [/\bChrome\b/i, "Google Chrome"],
    [/\bFirefox\b/i, "Mozilla Firefox"],
    [/\bWordPress\b/i, "WordPress"],
    [/\bVeeam\b/i, "Veeam"],
    [/\bIOS XE\b/i, "Cisco IOS XE"],
    [/\bASA\b/i, "Cisco ASA"],
  ];

  for (const [pattern, product] of productPatterns) {
    if (pattern.test(combined) && !products.includes(product)) {
      products.push(product);
    }
  }

  return products;
}

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------

function initDatabase(): Database.Database {
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  if (force && existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
    log(`Deleted existing database at ${DB_PATH}`);
  }

  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);
  log(`Database initialised at ${DB_PATH}`);
  return db;
}

// ---------------------------------------------------------------------------
// Framework seeding
// ---------------------------------------------------------------------------

interface FrameworkRow {
  id: string;
  name: string;
  name_en: string | null;
  description: string;
  document_count: number;
}

function seedFrameworks(db: Database.Database): void {
  const frameworks: FrameworkRow[] = [
    {
      id: "cfcs-vejledninger",
      name: "CFCS Vejledninger",
      name_en: "CFCS Guidance Publications",
      description:
        "Vejledninger og anbefalinger fra Center for Cybersikkerhed (CFCS) inden for cybersikkerhed, forebyggelse, haendelsesrespons og beskyttelse af kritisk infrastruktur.",
      document_count: 0, // updated after ingestion
    },
    {
      id: "cfcs-nationale-anbefalinger",
      name: "Nationale Anbefalinger",
      name_en: "National Recommendations",
      description:
        "CFCS nationale anbefalinger for cybersikkerhed i Danmark, herunder logning, emailsikkerhed, identitetssikring og patchhaandtering.",
      document_count: 0,
    },
    {
      id: "cfcs-trusselsvurderinger",
      name: "CFCS Trusselsvurderinger",
      name_en: "CFCS Threat Assessments",
      description:
        "Sektorspecifikke og nationale trusselsvurderinger fra CFCS, der beskriver cybertrusselsbilledet mod Danmark, herunder trusler fra statsstottede aktorer, cyberkriminalitet og hacktivisme.",
      document_count: 0,
    },
    {
      id: "nis2-dk",
      name: "NIS2 i Danmark",
      name_en: "NIS2 Directive Implementation in Denmark",
      description:
        "CFCS er national CSIRT og Erhvervsstyrelsen er koordinerende kompetent myndighed for NIS2-direktivet i Danmark. Vejledning for virksomheder der er omfattet af NIS2.",
      document_count: 0,
    },
    {
      id: "cfcs-varsler",
      name: "CFCS Varsler og Haendelser",
      name_en: "CFCS Alerts and Incidents",
      description:
        "Sikkerhedsadvarsler og varslinger udstedt af CFCS om aktive cybertrusler, sarbarheder under udnyttelse og sikkerhedshaendelser med relevans for danske organisationer.",
      document_count: 0,
    },
    {
      id: "cfcs-temasider",
      name: "CFCS Temasider",
      name_en: "CFCS Thematic Articles",
      description:
        "Tematiske artikler fra CFCS om specifikke cybersikkerhedsemner, herunder AI og cybersikkerhed, leverandorkaede sikkerhed og sektortrusler.",
      document_count: 0,
    },
  ];

  const insert = db.prepare(
    "INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
  );

  const insertAll = db.transaction(() => {
    for (const f of frameworks) {
      insert.run(f.id, f.name, f.name_en, f.description, f.document_count);
    }
  });

  insertAll();
  log(`Seeded ${frameworks.length} frameworks`);
}

// ---------------------------------------------------------------------------
// Guidance ingestion
// ---------------------------------------------------------------------------

async function ingestGuidancePages(
  db: Database.Database,
  state: IngestState,
): Promise<number> {
  log("--- Ingesting guidance pages (vejledninger + nationale anbefalinger) ---");

  const insertGuidance = db.prepare(`
    INSERT OR REPLACE INTO guidance
      (reference, title, title_en, date, type, series, summary, full_text, topics, status)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const completedSet = new Set(state.guidanceCompleted);
  let ingested = 0;
  let failed = 0;

  // 1. HTML guidance pages
  for (const urlPath of GUIDANCE_URLS) {
    const ref = urlToReference(urlPath, "CFCS-VEJ");
    if (completedSet.has(ref)) {
      log(`  [skip] ${ref} (already ingested)`);
      continue;
    }

    const fullUrl = `${CFCS_BASE}${urlPath}`;
    try {
      log(`  Fetching ${fullUrl}`);
      const html = await fetchHtml(fullUrl);
      const title = extractTitle(html);
      const content = extractMainContent(html);
      const date = extractDate(html);
      const summary = extractSummary(html);
      const type = classifyGuidanceType(urlPath, title);
      const series = classifyGuidanceSeries(urlPath);
      const topics = extractTopics(content, title);

      if (content.length < 50) {
        warn(`  Skipping ${urlPath}: insufficient content (${content.length} chars)`);
        failed++;
        continue;
      }

      if (dryRun) {
        log(
          `  [DRY-RUN] Would insert guidance ${ref}: "${title}" (${type}, ${content.length} chars)`,
        );
      } else {
        insertGuidance.run(
          ref,
          title,
          null, // title_en — not available on Danish pages
          date,
          type,
          series,
          summary,
          content,
          topics,
          "current",
        );
      }

      state.guidanceCompleted.push(ref);
      ingested++;
      log(
        `  [${ingested}] ${ref}: "${title}" (${type}, ${content.length} chars)`,
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logError(`  Failed to ingest ${urlPath}: ${msg}`);
      failed++;
    }

    saveState(state);
  }

  // 2. PDF guidance documents (metadata only)
  for (const pdfPath of GUIDANCE_PDF_URLS) {
    const ref = pdfUrlToReference(pdfPath, "CFCS-PDF");
    if (completedSet.has(ref)) {
      log(`  [skip] ${ref} (already ingested)`);
      continue;
    }

    const fullUrl = `${CFCS_BASE}${pdfPath}`;
    try {
      log(`  Fetching PDF metadata: ${fullUrl}`);
      const meta = await fetchPdfMetadata(fullUrl);
      if (!meta.ok) {
        warn(`  PDF not accessible: ${pdfPath}`);
        failed++;
        continue;
      }

      // Extract title from filename
      const filename = pdfPath.split("/").pop() ?? "unknown";
      const title = filename
        .replace(/\.pdf$/i, "")
        .replace(/^-+|-+$/g, "")
        .replace(/-/g, " ")
        .replace(/\s+/g, " ")
        .trim();

      const date = extractYearFromUrl(pdfPath);
      const series = pdfPath.includes("vejledninger")
        ? "CFCS Vejledninger"
        : "CFCS";
      const type = "guidance";

      const fullText =
        `[PDF-dokument] ${title}. ` +
        `Downloades fra: ${fullUrl}. ` +
        `Filstorrelse: ${Math.round(meta.size / 1024)} KB. ` +
        `Dette er et PDF-dokument fra Center for Cybersikkerhed (CFCS). ` +
        `Fuld tekst kraever PDF-laesning — se den originale fil for indholdet.`;

      const summary = `CFCS vejledningsdokument: ${title}. Tilgaengeligt som PDF fra cfcs.dk.`;
      const topics = extractTopics(title + " " + fullText, title);

      if (dryRun) {
        log(
          `  [DRY-RUN] Would insert PDF guidance ${ref}: "${title}" (${Math.round(meta.size / 1024)} KB)`,
        );
      } else {
        insertGuidance.run(
          ref,
          title,
          null,
          date,
          type,
          series,
          summary,
          fullText,
          topics,
          "current",
        );
      }

      state.guidanceCompleted.push(ref);
      ingested++;
      log(
        `  [${ingested}] ${ref}: "${title}" (PDF, ${Math.round(meta.size / 1024)} KB)`,
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logError(`  Failed to ingest PDF ${pdfPath}: ${msg}`);
      failed++;
    }

    saveState(state);
  }

  // 3. Discover additional guidance links from the forebyggelse page
  try {
    log("  Discovering additional guidance links from /da/forebyggelse/...");
    const forebyggelseHtml = await fetchHtml(`${CFCS_BASE}/da/forebyggelse/`);
    const links = extractLinks(
      forebyggelseHtml,
      /\/da\/forebyggelse\/vejledninger\//,
    );

    for (const link of links) {
      const ref = urlToReference(link.href, "CFCS-VEJ");
      if (completedSet.has(ref) || state.guidanceCompleted.includes(ref)) {
        continue;
      }

      const fullUrl = link.href.startsWith("http")
        ? link.href
        : `${CFCS_BASE}${link.href}`;

      try {
        log(`  Fetching discovered link: ${fullUrl}`);
        const html = await fetchHtml(fullUrl);
        const title = extractTitle(html) || link.text;
        const content = extractMainContent(html);
        const date = extractDate(html);
        const summary = extractSummary(html);
        const type = classifyGuidanceType(link.href, title);
        const series = classifyGuidanceSeries(link.href);
        const topics = extractTopics(content, title);

        if (content.length < 50) {
          continue;
        }

        if (dryRun) {
          log(
            `  [DRY-RUN] Would insert discovered guidance ${ref}: "${title}"`,
          );
        } else {
          insertGuidance.run(
            ref,
            title,
            null,
            date,
            type,
            series,
            summary,
            content,
            topics,
            "current",
          );
        }

        state.guidanceCompleted.push(ref);
        ingested++;
        log(`  [${ingested}] ${ref}: "${title}" (discovered, ${content.length} chars)`);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        warn(`  Could not ingest discovered link ${link.href}: ${msg}`);
      }

      saveState(state);
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    warn(`  Could not discover additional guidance links: ${msg}`);
  }

  log(
    `Guidance ingestion complete: ${ingested} inserted, ${failed} failed`,
  );
  return ingested;
}

// ---------------------------------------------------------------------------
// Threat assessment ingestion (-> advisories table)
// ---------------------------------------------------------------------------

async function ingestThreatAssessments(
  db: Database.Database,
  state: IngestState,
): Promise<number> {
  log("--- Ingesting threat assessments (trusselsvurderinger) ---");

  const insertAdvisory = db.prepare(`
    INSERT OR REPLACE INTO advisories
      (reference, title, date, severity, affected_products, summary, full_text, cve_references)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const completedSet = new Set(state.advisoriesCompleted);
  let ingested = 0;
  let failed = 0;

  // 1. HTML threat assessment pages
  for (const urlPath of THREAT_ASSESSMENT_URLS) {
    const ref = urlToReference(urlPath, "CFCS-TV");
    if (completedSet.has(ref)) {
      log(`  [skip] ${ref} (already ingested)`);
      continue;
    }

    const fullUrl = `${CFCS_BASE}${urlPath}`;
    try {
      log(`  Fetching ${fullUrl}`);
      const html = await fetchHtml(fullUrl);
      const title = extractTitle(html);
      const content = extractMainContent(html);
      const date = extractDate(html);
      const summary = extractSummary(html);
      const severity = classifyThreatSeverity(content);
      const cves = extractCves(content);

      // For threat assessments, affected_products is the sector
      const sectorProducts: string[] = [];
      const titleLower = (title + " " + urlPath).toLowerCase();
      if (titleLower.includes("finans")) sectorProducts.push("Finansiel sektor");
      if (titleLower.includes("søfart") || titleLower.includes("soefart"))
        sectorProducts.push("Soefart");
      if (titleLower.includes("transport")) sectorProducts.push("Transportsektoren");
      if (titleLower.includes("sundhed")) sectorProducts.push("Sundhedssektoren");
      if (titleLower.includes("tele")) sectorProducts.push("Telesektoren");
      if (titleLower.includes("forsvar")) sectorProducts.push("Forsvarsindustrien");
      if (titleLower.includes("grønland") || titleLower.includes("gronland"))
        sectorProducts.push("Gronland");
      if (titleLower.includes("energi")) sectorProducts.push("Energisektoren");
      if (titleLower.includes("vand")) sectorProducts.push("Vandsektoren");
      if (titleLower.includes("rum")) sectorProducts.push("Rumsektoren");
      if (titleLower.includes("universitet")) sectorProducts.push("Universitetssektoren");
      if (sectorProducts.length === 0) sectorProducts.push("Alle sektorer");

      if (content.length < 50) {
        warn(`  Skipping ${urlPath}: insufficient content (${content.length} chars)`);
        failed++;
        continue;
      }

      if (dryRun) {
        log(
          `  [DRY-RUN] Would insert threat assessment ${ref}: "${title}" (${severity})`,
        );
      } else {
        insertAdvisory.run(
          ref,
          title,
          date,
          severity,
          JSON.stringify(sectorProducts),
          summary,
          content,
          cves.length > 0 ? JSON.stringify(cves) : null,
        );
      }

      state.advisoriesCompleted.push(ref);
      ingested++;
      log(
        `  [${ingested}] ${ref}: "${title}" (${severity}, ${content.length} chars)`,
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logError(`  Failed to ingest ${urlPath}: ${msg}`);
      failed++;
    }

    saveState(state);
  }

  // 2. PDF threat assessments (metadata only)
  for (const pdfPath of THREAT_PDF_URLS) {
    const ref = pdfUrlToReference(pdfPath, "CFCS-TV-PDF");
    if (completedSet.has(ref)) {
      log(`  [skip] ${ref} (already ingested)`);
      continue;
    }

    const fullUrl = `${CFCS_BASE}${pdfPath}`;
    try {
      log(`  Fetching PDF metadata: ${fullUrl}`);
      const meta = await fetchPdfMetadata(fullUrl);
      if (!meta.ok) {
        warn(`  PDF not accessible: ${pdfPath}`);
        failed++;
        continue;
      }

      const filename = pdfPath.split("/").pop() ?? "unknown";
      const title = filename
        .replace(/\.pdf$/i, "")
        .replace(/^-+|-+$/g, "")
        .replace(/-/g, " ")
        .replace(/\s+/g, " ")
        .trim();

      const date = extractYearFromUrl(pdfPath);

      // Determine sector from filename
      const sectorProducts: string[] = [];
      const lower = filename.toLowerCase();
      if (lower.includes("vand")) sectorProducts.push("Vandsektoren");
      if (lower.includes("tele")) sectorProducts.push("Telesektoren");
      if (lower.includes("rum")) sectorProducts.push("Rumsektoren");
      if (lower.includes("sundhed")) sectorProducts.push("Sundhedssektoren");
      if (lower.includes("universitet") || lower.includes("forskning"))
        sectorProducts.push("Universitetssektoren");
      if (lower.includes("danmark")) sectorProducts.push("Alle sektorer");
      if (sectorProducts.length === 0) sectorProducts.push("Alle sektorer");

      const fullText =
        `[PDF-dokument] ${title}. ` +
        `Downloades fra: ${fullUrl}. ` +
        `Filstorrelse: ${Math.round(meta.size / 1024)} KB. ` +
        `Trusselsvurdering fra Center for Cybersikkerhed (CFCS). ` +
        `Fuld tekst kraever PDF-laesning — se den originale fil for indholdet.`;

      const summary = `CFCS trusselsvurdering: ${title}. Tilgaengeligt som PDF fra cfcs.dk.`;

      if (dryRun) {
        log(
          `  [DRY-RUN] Would insert threat PDF ${ref}: "${title}" (${Math.round(meta.size / 1024)} KB)`,
        );
      } else {
        insertAdvisory.run(
          ref,
          title,
          date,
          "high", // Threat assessments are high-level documents
          JSON.stringify(sectorProducts),
          summary,
          fullText,
          null,
        );
      }

      state.advisoriesCompleted.push(ref);
      ingested++;
      log(
        `  [${ingested}] ${ref}: "${title}" (PDF, ${Math.round(meta.size / 1024)} KB)`,
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logError(`  Failed to ingest threat PDF ${pdfPath}: ${msg}`);
      failed++;
    }

    saveState(state);
  }

  // 3. Discover additional threat assessment links from the overview page
  try {
    log("  Discovering additional threat assessments from overview page...");
    const overviewHtml = await fetchHtml(
      `${CFCS_BASE}/da/cybertruslen/trusselsvurderinger/`,
    );
    const links = extractLinks(
      overviewHtml,
      /\/da\/cybertruslen\/trusselsvurderinger\/[^/]+\/?$/,
    );

    for (const link of links) {
      const ref = urlToReference(link.href, "CFCS-TV");
      if (completedSet.has(ref) || state.advisoriesCompleted.includes(ref)) {
        continue;
      }

      const fullUrl = link.href.startsWith("http")
        ? link.href
        : `${CFCS_BASE}${link.href}`;

      try {
        log(`  Fetching discovered threat assessment: ${fullUrl}`);
        const html = await fetchHtml(fullUrl);
        const title = extractTitle(html) || link.text;
        const content = extractMainContent(html);
        const date = extractDate(html);
        const summary = extractSummary(html);
        const severity = classifyThreatSeverity(content);

        if (content.length < 50) continue;

        if (dryRun) {
          log(
            `  [DRY-RUN] Would insert discovered threat assessment ${ref}: "${title}"`,
          );
        } else {
          insertAdvisory.run(
            ref,
            title,
            date,
            severity,
            JSON.stringify(["Alle sektorer"]),
            summary,
            content,
            null,
          );
        }

        state.advisoriesCompleted.push(ref);
        ingested++;
        log(
          `  [${ingested}] ${ref}: "${title}" (discovered, ${severity})`,
        );
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        warn(`  Could not ingest discovered assessment ${link.href}: ${msg}`);
      }

      saveState(state);
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    warn(`  Could not discover additional threat assessments: ${msg}`);
  }

  log(
    `Threat assessment ingestion complete: ${ingested} inserted, ${failed} failed`,
  );
  return ingested;
}

// ---------------------------------------------------------------------------
// Alert ingestion (varsler -> advisories table)
// ---------------------------------------------------------------------------

async function ingestAlerts(
  db: Database.Database,
  state: IngestState,
): Promise<number> {
  log("--- Ingesting alerts (varsler) ---");

  const insertAdvisory = db.prepare(`
    INSERT OR REPLACE INTO advisories
      (reference, title, date, severity, affected_products, summary, full_text, cve_references)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const completedSet = new Set(state.alertsCompleted);
  let ingested = 0;
  let failed = 0;

  // Fetch the alerts listing page
  const alertsUrl = `${CFCS_BASE}${ALERTS_INDEX_URL}`;
  let alertLinks: Array<{ href: string; text: string }> = [];

  try {
    log(`  Fetching alerts index: ${alertsUrl}`);
    const html = await fetchHtml(alertsUrl);
    alertLinks = extractLinks(html, /\/da\/handelser\/varsler\/[^/]+\/?$/);
    log(`  Found ${alertLinks.length} alert links`);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logError(`  Failed to fetch alerts index: ${msg}`);
    return 0;
  }

  for (const link of alertLinks) {
    const ref = urlToReference(link.href, "CFCS-VARSEL");
    if (completedSet.has(ref)) {
      log(`  [skip] ${ref} (already ingested)`);
      continue;
    }

    const fullUrl = link.href.startsWith("http")
      ? link.href
      : `${CFCS_BASE}${link.href}`;

    try {
      log(`  Fetching alert: ${fullUrl}`);
      const html = await fetchHtml(fullUrl);
      const title = extractTitle(html) || link.text;
      const content = extractMainContent(html);
      const date = extractDate(html);
      const summary = extractSummary(html);
      const cves = extractCves(content);
      const severity = cves.length > 0 ? "high" : classifyThreatSeverity(content);
      const products = extractAffectedProducts(content, title);

      if (content.length < 30) {
        warn(`  Skipping alert ${link.href}: insufficient content`);
        failed++;
        continue;
      }

      if (dryRun) {
        log(
          `  [DRY-RUN] Would insert alert ${ref}: "${title}" (${severity}, ${cves.length} CVEs)`,
        );
      } else {
        insertAdvisory.run(
          ref,
          title,
          date,
          severity,
          products.length > 0 ? JSON.stringify(products) : null,
          summary,
          content,
          cves.length > 0 ? JSON.stringify(cves) : null,
        );
      }

      state.alertsCompleted.push(ref);
      ingested++;
      log(
        `  [${ingested}] ${ref}: "${title}" (${severity}, ${cves.length} CVEs)`,
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logError(`  Failed to ingest alert ${link.href}: ${msg}`);
      failed++;
    }

    saveState(state);
  }

  log(`Alert ingestion complete: ${ingested} inserted, ${failed} failed`);
  return ingested;
}

// ---------------------------------------------------------------------------
// Framework document count update
// ---------------------------------------------------------------------------

function updateFrameworkCounts(db: Database.Database): void {
  const seriesMap: Record<string, string> = {
    "CFCS Vejledninger": "cfcs-vejledninger",
    Forebyggelse: "cfcs-vejledninger",
    "Nationale Anbefalinger": "cfcs-nationale-anbefalinger",
    Temasider: "cfcs-temasider",
    CFCS: "cfcs-vejledninger",
  };

  // Count guidance per series
  const guidanceCounts = db
    .prepare("SELECT series, COUNT(*) as cnt FROM guidance GROUP BY series")
    .all() as Array<{ series: string; cnt: number }>;

  for (const row of guidanceCounts) {
    const frameworkId = seriesMap[row.series] ?? "cfcs-vejledninger";
    db.prepare(
      "UPDATE frameworks SET document_count = document_count + ? WHERE id = ?",
    ).run(row.cnt, frameworkId);
  }

  // Count advisories for threat assessment and alert frameworks
  const advisoryCount = (
    db.prepare("SELECT COUNT(*) as cnt FROM advisories").get() as {
      cnt: number;
    }
  ).cnt;

  const threatPdfCount = (
    db
      .prepare(
        "SELECT COUNT(*) as cnt FROM advisories WHERE reference LIKE 'CFCS-TV%'",
      )
      .get() as { cnt: number }
  ).cnt;
  const alertCount = advisoryCount - threatPdfCount;

  db.prepare("UPDATE frameworks SET document_count = ? WHERE id = ?").run(
    threatPdfCount,
    "cfcs-trusselsvurderinger",
  );
  db.prepare("UPDATE frameworks SET document_count = ? WHERE id = ?").run(
    alertCount,
    "cfcs-varsler",
  );

  log("Updated framework document counts");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  log("=== CFCS Ingestion Crawler ===");
  log(
    `Mode: ${dryRun ? "DRY-RUN" : "live"} | Resume: ${resume} | Force: ${force}`,
  );
  if (advisoriesOnly) log("Scope: advisories only");
  if (guidanceOnly) log("Scope: guidance only");

  const db = dryRun ? null : initDatabase();
  const state = loadState();

  if (!dryRun && db) {
    seedFrameworks(db);
  }

  // For dry-run we still need a DB handle to prepare statements (even though
  // we never call .run). Create a throwaway in-memory DB.
  const effectiveDb = db ?? new Database(":memory:");
  if (!db) {
    effectiveDb.exec(SCHEMA_SQL);
  }

  let totalGuidance = 0;
  let totalAdvisories = 0;
  let totalAlerts = 0;

  if (!advisoriesOnly) {
    totalGuidance = await ingestGuidancePages(effectiveDb, state);
  }

  if (!guidanceOnly) {
    totalAdvisories = await ingestThreatAssessments(effectiveDb, state);
    totalAlerts = await ingestAlerts(effectiveDb, state);
  }

  // Update framework document counts
  if (!dryRun && db) {
    updateFrameworkCounts(db);
  }

  // Final summary
  if (!dryRun && db) {
    const guidanceCount = (
      db.prepare("SELECT COUNT(*) as cnt FROM guidance").get() as {
        cnt: number;
      }
    ).cnt;
    const advisoryCount = (
      db.prepare("SELECT COUNT(*) as cnt FROM advisories").get() as {
        cnt: number;
      }
    ).cnt;
    const frameworkCount = (
      db.prepare("SELECT COUNT(*) as cnt FROM frameworks").get() as {
        cnt: number;
      }
    ).cnt;

    log("\nDatabase summary:");
    log(`  Frameworks:         ${frameworkCount}`);
    log(`  Guidance documents: ${guidanceCount}`);
    log(`  Advisories/alerts:  ${advisoryCount}`);
    db.close();
  }

  log("\nIngestion results (this run):");
  log(`  Guidance inserted:           ${totalGuidance}`);
  log(`  Threat assessments inserted: ${totalAdvisories}`);
  log(`  Alerts inserted:             ${totalAlerts}`);
  log(`  Total:                       ${totalGuidance + totalAdvisories + totalAlerts}`);

  saveState(state);
  log(`\nState saved to ${STATE_FILE}`);
  log(`Database at ${DB_PATH}`);
  log("Done.");
}

main().catch((err) => {
  logError(`Fatal: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
