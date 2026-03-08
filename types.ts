

export type Certificate = {
  id: string;
  title: string;
  issuer: string;
  description: string;
  date: number;
  pdfUrl: string;
  verifyUrl: string;
  category: string;
};

export type User = {
  id: string;
  username: string;
  name: string;
  email: string;
  password: string;
  certs: string[];
  intentos: number;
};