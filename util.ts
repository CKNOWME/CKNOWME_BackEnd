import { CredlyBadge, CredlySkill,LinkedInCertification } from "./types.ts";
import { getuserJWT } from "./auth.ts";
import { Request } from "express";
import { DOMParser, Element } from "https://deno.land/x/deno_dom@v0.1.49/deno-dom-wasm.ts";
import multer from "multer";



export const MAX_LOGIN_ATTEMPTS = 5;
export const MAX_PHOTO_SIZE = 2 * 1024 * 1024; // 2MB
export const MAX_CV_SIZE = 4 * 1024 * 1024; // 4MB
export const ALLOWED_MIME = ["image/png", "image/jpeg", "image/jpg"];
export const CV_MIME = ["application/pdf"];

export const buildAuthCookie = (token: string): string => {
  return `bearer=${token}; Path=/; SameSite=Lax; Max-Age=3600; HttpOnly; Secure`;
};
export const clearAuthCookie = (): string => {
  return `bearer=; Path=/; SameSite=Lax; Max-Age=0; HttpOnly; Secure`;
};
export const buildCsrfCookie = (token: string): string => {
  return `csrf=${token}; Path=/; SameSite=Lax; Max-Age=3600; Secure`;
};
export const isEmailValid = (email: string): boolean => {
  return email.includes("@") && email.includes(".");
};
export const isValidImageBuffer = (buffer: Uint8Array, mime: string): boolean => {
  if (mime === "image/png") {
    return buffer.length >= 8 &&
      buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47 &&
      buffer[4] === 0x0d && buffer[5] === 0x0a && buffer[6] === 0x1a && buffer[7] === 0x0a;
  }
  if (mime === "image/jpeg" || mime === "image/jpg") {
    return buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  }
  return false;
};
export const isValidPdfBuffer = (buffer: Uint8Array): boolean => {
  return buffer.length >= 4 && buffer[0] == 0x25 && buffer[1] == 0x50 && buffer[2] == 0x44 && buffer[3] == 0x46;
};
export const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_PHOTO_SIZE },
  fileFilter: (_req: any, file: any, cb: any) => {
    if (!ALLOWED_MIME.includes(file.mimetype)) {
      return cb(new Error("Invalid file type"));
    }
    cb(null, true);
  },
});
export const uploadCv = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_CV_SIZE },
  fileFilter: (_req: any, file: any, cb: any) => {
    if (!CV_MIME.includes(file.mimetype)) {
      return cb(new Error("Invalid file type"));
    }
    cb(null, true);
  },
});




export const PRIVATE_IPS = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^169\.254\./,
  /^0\./,
  /^::1$/,
  /^localhost$/i,
];
export const PRIVATE_IP_RANGES = [/^172\.(1[6-9]|2\d|3[0-1])\./];

export const isPrivateHost = (hostname: string): boolean => {
  return PRIVATE_IPS.some((rule) => rule.test(hostname)) ||
    PRIVATE_IP_RANGES.some((rule) => rule.test(hostname));
};
export const validatePublicUrl = (rawUrl: string): boolean => {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return false;
    }
    if (isPrivateHost(parsed.hostname)) return false;
    return true;
  } catch {
    return false;
  }
};
export const ensureSafeUrls = (urls: string[]): boolean => {
  for (const url of urls) {
    if (!url) continue;
    if (!validatePublicUrl(url)) return false;
  }
  return true;
};
export const parseDate = (value?: string | null): number | null => {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
};
export const resolveAuthUser = async (req: Request): Promise<string | null> => {
  const jwt = req.cookies?.bearer;
  if (!jwt) return null;
  const username = await getuserJWT(jwt);
  if (username === "error") return null;
  return username;
};
export const normalizeOptionalUrl = (value: unknown): string => {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  if (!trimmed) return "";
  return trimmed;
};
export const normalizeHash = (value: unknown): string => {
  if (typeof value !== "string") return "";
  const cleaned = value.trim().toLowerCase();
  if (!cleaned) return "";
  if (!/^[a-f0-9]{64}$/.test(cleaned)) return "";
  return cleaned;
};


export const extractCredlySlug = (rawUrl: string): string | null => {
  try {
    const parsed = new URL(rawUrl);
    const host = parsed.hostname.toLowerCase();
    if (host !== "www.credly.com" && host !== "credly.com") return null;
    if (!validatePublicUrl(rawUrl)) return null;

    const path = parsed.pathname.replace(/\/+$/, "");
    if (path.startsWith("/users/")) {
      const slug = path.split("/")[2];
      return slug || null;
    }
  } catch (_err: Error | unknown) {
    return null;
  }
  return null
};
export const badgeEndpointFor = (slug: string): string => {
  return `https://www.credly.com/users/${slug}`;
};
export const getCredlyBadges = async (id:string):Promise<CredlyBadge[] | null>=>{
  const url = `https://www.credly.com/users/${id}/badges`;
  const res = await fetch(url, {
    headers: {
      "Accept": "application/json",
      "X-Requested-With": "XMLHttpRequest",
      "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
      "Accept-Language": "es-ES,es;q=0.9",
      "Sec-Ch-Ua": '"Chromium";v="145", "Not:A-Brand";v="99"',
      "Sec-Ch-Ua-Mobile": "?0",
      "Sec-Ch-Ua-Platform": '"macOS"',
      "Sec-Fetch-Site": "same-origin",
      "Sec-Fetch-Mode": "cors",
      "Sec-Fetch-Dest": "empty",
      "Accept-Encoding": "gzip, deflate, br",
      "Priority": "u=1, i",
    },
  });
  if(!res.ok){
    const body = await res.text();
    return null;
  }
  const text = await res.text();
  if (text.trim().startsWith("<")) {
    return null;
  }
  const data = JSON.parse(text);
  return data.data;
}
export const normalizeTags = (skills?: CredlySkill[]): string[] => {
  if (!skills) return [];
  return skills
    .map((s) => (s?.name || "").trim())
    .filter(Boolean)
    .slice(0, 12);
};
export const issuerFrom = (badge: CredlyBadge): string => {
  const templateIssuer = badge.badge_template?.issuer?.entities?.[0]?.entity
    ?.name;
  if (templateIssuer) return templateIssuer;
  const issuerEntity = badge.issuer?.entities?.[0]?.entity?.name;
  if (issuerEntity) return issuerEntity;
  const summary = badge.issuer?.summary || "";
  if (summary.toLowerCase().startsWith("issued by ")) {
    return summary.slice("issued by ".length).trim() || "Credly";
  }
  return summary || "Credly";
};

const MONTHS: Record<string, number> = {
  ene: 0,
  feb: 1,
  mar: 2,
  abr: 3,
  may: 4,
  jun: 5,
  jul: 6,
  ago: 7,
  sep: 8,
  sept: 8,
  oct: 9,
  nov: 10,
  dic: 11,
  jan: 0,
  apr: 3,
  aug: 7,
  dec: 11,
};
const parseMonthYear = (value: string): number | null => {
  const match = value.toLowerCase().match(
    /(ene|feb|mar|abr|may|jun|jul|ago|sep|sept|oct|nov|dic|jan|apr|aug|dec)\.?\s+(\d{4})/i,
  );
  if (!match) return null;
  const key = match[1].replace(".", "");
  const month = MONTHS[key];
  if (month === undefined) return null;
  const year = parseInt(match[2], 10);
  if (Number.isNaN(year)) return null;
  return Date.UTC(year, month, 1);
};
const parseLinkedInDates = (dates: string | null): { issuedAt: number | null; expiresAt: number | null } => {
  if (!dates) return { issuedAt: null, expiresAt: null };
  const issuedMatch = dates.match(/Expedici[oó]n\s+([^·]+)/i) || dates.match(/Issued\s+([^·]+)/i);
  const expiresMatch = dates.match(/Vencimiento:?\s*([^·]+)/i) || dates.match(/Expiration:?\s*([^·]+)/i);
  const issuedAt = issuedMatch ? parseMonthYear(issuedMatch[1].trim()) : null;
  const expiresAt = expiresMatch ? parseMonthYear(expiresMatch[1].trim()) : null;
  return { issuedAt, expiresAt };
};
function parseCertification(el: Element): LinkedInCertification {
  const nameEl = el.querySelector(".t-bold span[aria-hidden='true']");
  const name = nameEl?.textContent?.trim() ?? null;

  const companySpans = el.querySelectorAll(".t-14.t-normal span[aria-hidden='true']");
  const company = companySpans[0]?.textContent?.trim() ?? null;

  const metaSpans = el.querySelectorAll(
    ".t-14.t-normal.t-black--light span[aria-hidden='true']"
  );
  let dates: string | null = null;
  let credentialId: string | null = null;

  for (const span of metaSpans) {
    const text = span.textContent?.trim();
    if (!text) continue;

    if (/ID de la credencial|credential ID/i.test(text) || /^\d+$/.test(text)) {
      credentialId = text.replace(/^ID de la credencial\s*/i, "").trim();
    } else {
      dates = text;
    }
  }

  const links = Array.from(el.querySelectorAll("a[href]"));
  const hrefs = links
    .map((link) => link.getAttribute("href"))
    .filter((href): href is string => Boolean(href && href.startsWith("http")));
  const url = hrefs.find((href) =>
    !href.includes("linkedin.com/") &&
    !href.includes("lnkd.in/")
  ) ?? null;

  const imgEl =
    el.querySelector(".pvs-thumbnail__image") ||
    el.querySelector(".pvs-entity__image img");
  const image = imgEl?.getAttribute("src") ?? null;

  const { issuedAt, expiresAt } = parseLinkedInDates(dates);

  return { name, company, dates, issuedAt, expiresAt, credentialId, url, image };
}
export function parseLinkedInCertifications(html: string): LinkedInCertification[] {
  const doc = new DOMParser().parseFromString(html, "text/html");
  if (!doc) return [];

  const certElements = doc.querySelectorAll(
    '[data-view-name="profile-component-entity"]'
  );

  return Array.from(certElements).map((el) => parseCertification(el));
}




