import { AuthorizationCode } from "simple-oauth2";

const client = () => new AuthorizationCode({
  client: {
    id: process.env.OAUTH_CLIENT_ID,
    secret: process.env.OAUTH_CLIENT_SECRET,
  },
  auth: {
    tokenHost: "https://github.com",
    tokenPath: "/login/oauth/access_token",
    authorizePath: "/login/oauth/authorize",
  },
});

export default async function handler(req, res) {
  // Step 1: redirect editor to GitHub auth
  if (req.method === "GET" && !req.query.code) {
    const authorizationUri = client().authorizeURL({
      redirect_uri: process.env.OAUTH_REDIRECT_URI,
      scope: "repo",
      state: "decap",
    });
    res.writeHead(302, { Location: authorizationUri });
    return res.end();
  }

  // Step 2: exchange code for token, then echo JSON per Decap spec
  if (req.method === "GET" && req.query.code) {
    try {
      const tokenParams = {
        code: req.query.code,
        redirect_uri: process.env.OAUTH_REDIRECT_URI,
      };
      const accessToken = await client().getToken(tokenParams);
      // CORS for your site
      res.setHeader("Access-Control-Allow-Origin", process.env.ALLOWED_ORIGIN);
      res.setHeader("Content-Type", "application/json");
      return res.status(200).send({
        token: accessToken.token.access_token,
      });
    } catch (e) {
      return res.status(400).send({ error: "oauth_exchange_failed" });
    }
  }

  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Origin", process.env.ALLOWED_ORIGIN);
    res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    return res.status(204).end();
  }

  return res.status(405).end();
}
