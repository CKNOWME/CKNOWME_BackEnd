

export type Certificate = {
  id: string;
  title: string;
  issuer: string;
  description: string;
  date: number;
  pdfUrl: string;
  verifyUrl: string;
  photo:string;
  cv:string;
  category: string;
};

export type User = {
  id: string;
  username: string;
  name: string;
  email: string;
  password: string;
  photo:string;
  cv:string;
  certs: string[];
  intentos: number;
};

export type CredlySkill = { name?: string };

export type CredlyIssuerEntity = {
  entity?: { name?: string };
};

export type CredlyIssuer = {
  summary?: string;
  entities?: CredlyIssuerEntity[];
};

export type CredlyBadgeTemplate = {
  name?: string;
  description?: string;
  image_url?: string;
  skills?: CredlySkill[];
  url?: string;
  type_category?: string | null;
  issuer?: CredlyIssuer;
};

export type CredlyBadge = {
  id: string;
  issued_at_date?: string;
  expires_at_date?: string | null;
  public?: boolean;
  issuer?: CredlyIssuer;
  badge_template?: CredlyBadgeTemplate;
  image_url?: string;
};

export type CredlyResponse = {
  data?: CredlyBadge[];
};

export type LinkedInCertification ={
  name: string | null;
  company: string | null;
  dates: string | null;
  issuedAt: number | null;
  expiresAt: number | null;
  credentialId: string | null;
  url: string | null;
  image: string | null;
}
