# CKNOWME BackEnd

API REST de CKNOWME construida con Express + TypeScript sobre Deno, conectada a
MongoDB con Mongoose.

## Stack

- Deno
- Express
- Mongoose (MongoDB)
- JWT (`jose`)
- Seguridad

## Estructura

- `server.ts`: bootstrap y montaje de rutas.
- `security.ts`: headers, rate limit, cache-control, guards anti XSS/SSRF/NoSQL
  injection.
- `auth.ts`: autorización admin/usuario.
- `util.ts`: utilidades y helpers.
- `DB/`: modelos (`user`, `cert`).
- `routes/`: endpoints.

## Variables de entorno

```env
MONGO_URI=mongodb://
PORT=3000
JWT_SECRET=secret123
```

## Ejecución

```bash
deno task start
```

Puerto por defecto: `3000`.

## Endpoints principales

### Auth

- `POST /login`
- `POST /me`
- `POST /register`

### Certificados

- `POST /add`
- `GET /all` 
- `GET /id/:id` 

### OAuth

- `POST /credly/import`
- `POST /linkedin/import-html` 

## Seguridad aplicada

- Hash de passwords con `bcryptjs`.
- JWT firmado con `JWT_SECRET`.
- Headers y hardening global en middleware.
