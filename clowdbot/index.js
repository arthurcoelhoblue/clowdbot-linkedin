import crypto from "crypto";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";

const app = express();
app.use(cookieParser());

const port = process.env.PORT || 8080;

const CLIENT_ID = process.env.LINKEDIN_CLIENT_ID || "";
const CLIENT_SECRET = process.env.LINKEDIN_CLIENT_SECRET || "";
const REDIRECT_URI = process.env.LINKEDIN_REDIRECT_URI || "";

const SCOPE = "openid profile email";

// MVP storage em memória (para teste). Em Cloud Run pode resetar.
const tokenStore = new Map();

function assertEnv() {
  const missing = [];
  if (!CLIENT_ID) missing.push("LINKEDIN_CLIENT_ID");
  if (!CLIENT_SECRET) missing.push("LINKEDIN_CLIENT_SECRET");
  if (!REDIRECT_URI) missing.push("LINKEDIN_REDIRECT_URI");
  if (missing.length) throw new Error(`Missing env vars: ${missing.join(", ")}`);
}

app.get("/", (req, res) => {
  res.type("text").send("clowdbot ok - v3-secure");
});

app.get("/auth/linkedin", (req, res) => {
  try {
    assertEnv();

    const state = crypto.randomBytes(16).toString("hex");

    res.cookie("li_oauth_state", state, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 10 * 60 * 1000
    });

    const params = new URLSearchParams({
      response_type: "code",
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: SCOPE,
      state
    });

    return res.redirect(`https://www.linkedin.com/oauth/v2/authorization?${params.toString()}`);
  } catch (e) {
    return res.status(500).type("text").send(e instanceof Error ? e.message : "Unexpected error");
  }
});

app.get("/oauth/linkedin/callback", async (req, res) => {
  const { code, state, error, error_description: errorDescription } = req.query;

  if (error) {
    return res.status(400).type("text").send(`LinkedIn authorization error: ${error} - ${errorDescription || ""}`);
  }
  if (!code) return res.status(400).type("text").send("Missing authorization code.");

  const expectedState = req.cookies?.li_oauth_state;
  if (!expectedState) return res.status(400).type("text").send("Missing stored state (cookie not found).");
  if (!state || String(state) !== String(expectedState)) {
    return res.status(400).type("text").send("Invalid state (possible CSRF).");
  }
  res.clearCookie("li_oauth_state");

  try {
    assertEnv();

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
      return res.status(tokenResponse.status).type("text").send(`Token exchange failed: ${JSON.stringify(payload)}`);
    }

    const decoded = jwt.decode(payload.id_token);
    if (!decoded || typeof decoded !== "object") return res.status(500).type("text").send("Unable to decode id_token.");
    if (decoded.aud !== CLIENT_ID) return res.status(400).type("text").send("Invalid id_token audience.");
    if (decoded.iss !== "https://www.linkedin.com/oauth") return res.status(400).type("text").send("Invalid id_token issuer.");

    const sub = decoded.sub;
    const expiresAt = Date.now() + (Number(payload.expires_in || 0) * 1000);

    tokenStore.set(sub, {
      access_token: payload.access_token,
      expires_at: expiresAt,
      scope: payload.scope,
      profile: { name: decoded.name, email: decoded.email, picture: decoded.picture }
    });

    return res.status(200).type("text").send(`LinkedIn conectado com sucesso para ${decoded.email || decoded.name || sub}.`);
  } catch (err) {
    return res.status(500).type("text").send(err instanceof Error ? err.message : "Unexpected error");
  }
});

app.listen(port, () => console.log(`clowdbot listening on port ${port}`));
