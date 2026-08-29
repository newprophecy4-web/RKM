import { jwtVerify, createRemoteJWKSet } from "jose";

const FIREBASE_JWKS = createRemoteJWKSet(
  new URL(
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
  )
);

function response(data, status = 200, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": env.CORS_ORIGIN || "*",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS"
    }
  });
}

async function firebaseUser(request, env) {
  const auth = request.headers.get("Authorization");

  if (!auth?.startsWith("Bearer ")) {
    throw new Error("UNAUTHORIZED");
  }

  const token = auth.substring(7);

  const { payload } = await jwtVerify(token, FIREBASE_JWKS, {
    algorithms: ["RS256"],
    issuer: `https://securetoken.google.com/${env.FIREBASE_PROJECT_ID}`,
    audience: env.FIREBASE_PROJECT_ID
  });

  return payload;
}

async function dbUser(uid, env) {
  return await env.DB.prepare(
    `SELECT * FROM users WHERE firebase_uid = ?`
  ).bind(uid).first();
}

export default {
  async fetch(request, env) {
    try {
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204 });
      }

      const url = new URL(request.url);
      const path = url.pathname;

      // Health check
      if (path === "/api/health") {
        const result = await env.DB
          .prepare("SELECT 1 AS ok")
          .first();

        return response({
          success: true,
          worker: "online",
          database: result?.ok === 1
        }, 200, env);
      }

      // Firebase authenticated user
      if (path === "/api/me") {
        const firebase = await firebaseUser(request, env);

        const user = await dbUser(firebase.sub, env);

        if (!user) {
          return response({
            success: false,
            message: "User profile not found"
          }, 404, env);
        }

        if (user.status !== "active") {
          return response({
            success: false,
            message: "Account is not active"
          }, 403, env);
        }

        return response({
          success: true,
          user
        }, 200, env);
      }

      // Admin-only users list
      if (path === "/api/users" && request.method === "GET") {
        const firebase = await firebaseUser(request, env);
        const admin = await dbUser(firebase.sub, env);

        if (!admin || admin.role !== "admin") {
          return response({
            success: false,
            message: "Admin access required"
          }, 403, env);
        }

        const { results } = await env.DB.prepare(
          `SELECT id, firebase_uid, name, email, phone,
                  photo_key, role, status,
                  address, date_of_birth, gender,
                  last_login_at, created_at, updated_at
           FROM users
           ORDER BY created_at DESC`
        ).all();

        return response({
          success: true,
          users: results
        }, 200, env);
      }

      // Create/update own profile
      if (path === "/api/profile" && request.method === "POST") {
        const firebase = await firebaseUser(request, env);
        const body = await request.json();

        const existing = await dbUser(firebase.sub, env);

        if (existing) {
          return response({
            success: true,
            message: "Profile already exists",
            user: existing
          }, 200, env);
        }

        const id = crypto.randomUUID();

        await env.DB.prepare(
          `INSERT INTO users
           (id, firebase_uid, name, email, phone, role, status)
           VALUES (?, ?, ?, ?, ?, 'user', 'active')`
        ).bind(
          id,
          firebase.sub,
          body.name || firebase.name || "User",
          firebase.email || body.email || null,
          body.phone || null
        ).run();

        const user = await dbUser(firebase.sub, env);

        return response({
          success: true,
          message: "Profile created",
          user
        }, 201, env);
      }

      return response({
        success: false,
        message: "Route not found"
      }, 404, env);

    } catch (error) {
      console.error(error);

      if (error.message === "UNAUTHORIZED") {
        return response({
          success: false,
          message: "Firebase authentication required"
        }, 401, env);
      }

      return response({
        success: false,
        message: "Internal server error"
      }, 500, env);
    }
  }
};
