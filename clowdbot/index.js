import crypto from "crypto";
import express from "express";

const app = express();

const port = process.env.PORT || 8080;

app.get("/", (req, res) => {
  res.type("text").send("clowdbot ok");
});

app.get("/auth/linkedin", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  const params = new URLSearchParams({
    response_type: "code",
    client_id: process.env.LINKEDIN_CLIENT_ID || "",
    redirect_uri: process.env.LINKEDIN_REDIRECT_URI || "",
    scope: "openid profile email",
    state,
  });

  const authUrl = `https://www.linkedin.com/oauth/v2/authorization?${params.toString()}`;
  res.redirect(authUrl);
});

app.get("/oauth/linkedin/callback", async (req, res) => {
  const { code, error, error_description: errorDescription } = req.query;

  if (error) {
    return res.status(400).json({
      error,
      error_description: errorDescription || "LinkedIn authorization error",
    });
  }

  if (!code) {
    return res.status(400).json({
      error: "missing_code",
      error_description: "Authorization code not provided.",
    });
  }

  try {
    const tokenResponse = await fetch("https://www.linkedin.com/oauth/v2/accessToken", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: String(code),
        redirect_uri: process.env.LINKEDIN_REDIRECT_URI || "",
        client_id: process.env.LINKEDIN_CLIENT_ID || "",
        client_secret: process.env.LINKEDIN_CLIENT_SECRET || "",
      }),
    });

    const payload = await tokenResponse.json();

    if (!tokenResponse.ok) {
      return res.status(tokenResponse.status).json({
        error: "token_exchange_failed",
        error_description: payload,
      });
    }

    return res.json(payload);
  } catch (err) {
    return res.status(500).json({
      error: "token_exchange_error",
      error_description: err instanceof Error ? err.message : "Unexpected error",
    });
  }
});

app.listen(port, () => {
  console.log(`clowdbot listening on port ${port}`);
});
