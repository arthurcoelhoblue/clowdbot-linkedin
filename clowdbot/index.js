import crypto from "crypto";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";

const app = express();
app.use(cookieParser());

const port = process.env.PORT || 8080;

// ⚠️ Carrega env vars (não deixe vazio em produção)
const CLIENT_ID = process.env.LINKEDIN_CLIENT_ID || "";
const CLIENT_SECRET = process.env.LINKEDIN_CLIENT_SECRET || "";
const REDIRECT_URI = process.env.LINKEDIN_REDIRECT_URI || "";

// OpenID Connect básico (login)
const SCOPE = "openid profile email";

// MVP storage em memória (para teste). Em Cloud Run pode resetar em restart/scale.
const tokenStore = new Map(); // key: sub, value: { access_token, expires_at, scope, profile }

function assertEnv() {
  const missing = [];
  if (!CLIENT_ID) missing.push("LINKEDIN_CLIENT_ID");
  if (!CLIENT_SECRET) missing.push("LINKEDIN_CLIENT_SECRET");
  if (!REDIRECT_URI) missing.push("LINKEDIN_REDIRECT_URI");

  if (missing.length) {
    throw new Error(`Missing env vars: ${missing.join(", ")}`);
  }
}

// ✅ Home: serve para confirmar qual revisão está no ar (carimbo)
app.get("/", (req, res) => {
  res.type("text").send("clowdbot ok - v3-secure");
});

// ✅ Inicia OAuth
app.get("/auth/linkedin", (req, res) => {
  try {
    assertEnv();

    // state anti-CSRF
    const state = crypto.randomBytes(16).toString("hex");

    // cookie httpOnly para armazenar state (não acessível via JS)
    res.cookie("li_oauth_state", state, {
      httpOnly: true,
      secure: true, // Cloud Run é HTTPS
      sameSite: "lax",
      maxAge: 10 * 60 * 1000 // 10 minutos
    });

    const params = new URLSearchParams({
      response_type: "code",
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: SCOPE,
      state
    });

    const authUrl = `https://www.linkedin.com/oauth/v2/authorization?${params.toString()}`;
    return res.redirect(authUrl);
  } catch (e) {
    return res.status(500).type("text").send(e instanceof Error ? e.message : "Unexpected error");
  }
});

// ✅ Callback OAuth
app.get("/oauth/linkedin/callback", async (req, res) => {
  const { code, state, error, error_description: errorDescription } = req.query;

  // LinkedIn devolve erro na query quando recusa
  if (error) {
    return res
      .status(400)
      .type("text")
      .send(`LinkedIn authorization error: ${String(error)} - ${String(errorDescription || "")}`);
  }

  if (!code) {
    return res.status(400).type("text").send("Missing authorization code.");
  }

  // valida state (anti-CSRF)
  const expectedState = req.cookies?.li_oauth_state;
  if (!expectedState) {
    return res.status(400).type("text").send("Missing stored state (cookie not found).");
  }
  if (!state || String(state) !== String(expectedState)) {
    return res.status(400).type("text").send("Invalid state (possible CSRF).");
  }

  // state ok: limpa cookie para evitar replay
  res.clearCookie("li_oauth_state");

  try {
    assertEnv();

    // troca code por token
    const tokenResponse = await fetch("https://www.linkedin.com/oauth/v2/accessToken", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: String(code),
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET
      })
    });

    const payload = await tokenResponse.json();

    if (!tokenResponse.ok) {
      // ⚠️ Evite logar payload completo em produção (pode conter info sensível)
      return res
        .status(tokenResponse.status)
        .type("text")
        .send(`Token exchange failed: ${JSON.stringify(payload)}`);
    }

    // NÃO retornar tokens. Apenas extrair identidade do id_token.
    const idToken = payload.id_token;
    const decoded = jwt.decode(idToken);

    if (!decoded || typeof decoded !== "object") {
      return res.status(500).type("text").send("Unable to decode id_token.");
    }

    // Checagens mínimas (MVP). Para produção, validamos assinatura via JWKS.
    if (decoded.aud !== CLIENT_ID) return res.status(400).type("text").send("Invalid id_token audience.");
    if (decoded.iss !== "https://www.linkedin.com/oauth") return res.status(400).type("text").send("Invalid id_token issuer.");

    const sub = decoded.sub;
    const expiresAt = Date.now() + (Number(payload.expires_in || 0) * 1000);

    tokenStore.set(sub, {
      access_token: payload.access_token, // guardado no servidor (MVP)
      expires_at: expiresAt,
      scope: payload.scope,
      profile: {
        name: decoded.name,
        email: decoded.email,
        picture: decoded.picture
      }
    });

    // ✅ resposta segura (SEM token)
    return res
      .status(200)
      .type("text")
      .send(`LinkedIn conectado com sucesso para ${decoded.email || decoded.name || sub}.`);
  } catch (err) {
    return res.status(500).type("text").send(err instanceof Error ? err.message : "Unexpected error");
  }
});

// ✅ Endpoint opcional: consulta perfil sem expor token
app.get("/me", (req, res) => {
  const sub = String(req.query.sub || "");
  if (!sub) return res.status(400).json({ error: "missing_sub" });

  const data = tokenStore.get(sub);
  if (!data) return res.status(404).json({ error: "not_found" });

  return res.json({
    sub,
    profile: data.profile,
    scope: data.scope,
    expires_at: data.expires_at
  });
});

app.listen(port, () => {
  console.log(`clowdbot listening on port ${port}`);
});
