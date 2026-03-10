import { CredlyBadge, CredlySkill } from "./types.ts";
import { getuserJWT } from "./auth.ts";
import { Request } from "express";

export const parseDate = (value?: string | null): number | null => {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
};

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

export const resolveAuthUser = async (req: Request): Promise<string | null> => {
  const jwt = req.cookies?.bearer;
  if (!jwt) return null;
  const username = await getuserJWT(jwt);
  if (username === "error") return null;
  return username;
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


