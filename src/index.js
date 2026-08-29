import { importX509, jwtVerify } from "jose";

/* =========================================================
   RKM - RAJARHAT KAMIL MADRASHA
   Cloudflare Worker API

   Firebase Authentication
        ↓
   Firebase ID Token
        ↓
   Cloudflare Worker
        ↓
   Cloudflare D1
========================================================= */

const json = (data, status = 200, origin = "*") =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Headers":
        "Content-Type, Authorization",
      "Access-Control-Allow-Methods":
        "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    },
  });

const error = (message, status = 400, origin = "*") =>
  json(
    {
      success: false,
      message,
    },
    status,
    origin
  );

const ok = (data = {}, origin = "*") =>
  json(
    {
      success: true,
      ...data,
    },
    200,
    origin
  );

/* =========================================================
   CORS
========================================================= */

function corsOrigin(env) {
  return env.CORS_ORIGIN || "*";
}

/* =========================================================
   Firebase Public Key Cache
========================================================= */

let firebaseKeys = null;
let firebaseKeysExpires = 0;

async function getFirebaseKeys() {
  const now = Date.now();

  if (firebaseKeys && now < firebaseKeysExpires) {
    return firebaseKeys;
  }

  const response = await fetch(
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
  );

  if (!response.ok) {
    throw new Error("Unable to load Firebase public keys");
  }

  firebaseKeys = await response.json();

  const cacheControl = response.headers.get("cache-control") || "";
  const match = cacheControl.match(/max-age=(\d+)/);

  const maxAge = match
    ? Number(match[1]) * 1000
    : 3600000;

  firebaseKeysExpires = now + maxAge;

  return firebaseKeys;
}

/* =========================================================
   Firebase ID Token Verification
========================================================= */

async function verifyFirebaseToken(token, projectId) {
  if (!token) {
    throw new Error("Missing Firebase token");
  }

  const keys = await getFirebaseKeys();

  const decoded = JSON.parse(
    atob(token.split(".")[0].replace(/-/g, "+").replace(/_/g, "/"))
  );

  const kid = decoded.kid;

  if (!kid || !keys[kid]) {
    throw new Error("Invalid Firebase token key");
  }

  const publicKey = await importX509(
    keys[kid],
    "RS256"
  );

  const { payload } = await jwtVerify(token, publicKey, {
    algorithms: ["RS256"],
    issuer: `https://securetoken.google.com/${projectId}`,
    audience: projectId,
  });

  if (payload.sub !== payload.user_id) {
    throw new Error("Invalid Firebase user");
  }

  return payload;
}

/* =========================================================
   Authentication Middleware
========================================================= */

async function requireAuth(request, env) {
  const header = request.headers.get("Authorization");

  if (!header || !header.startsWith("Bearer ")) {
    throw new Error("Authentication required");
  }

  const token = header.substring(7).trim();

  const firebaseUser = await verifyFirebaseToken(
    token,
    env.FIREBASE_PROJECT_ID
  );

  const uid = firebaseUser.user_id || firebaseUser.sub;

  if (!uid) {
    throw new Error("Invalid Firebase user");
  }

  return firebaseUser;
}

/* =========================================================
   Get D1 User
========================================================= */

async function getDbUser(env, firebaseUid) {
  return await env.DB
    .prepare(
      `
      SELECT *
      FROM users
      WHERE firebase_uid = ?
      LIMIT 1
      `
    )
    .bind(firebaseUid)
    .first();
}

/* =========================================================
   Admin Middleware
========================================================= */

async function requireAdmin(request, env) {
  const firebaseUser = await requireAuth(request, env);

  const user = await getDbUser(
    env,
    firebaseUser.user_id || firebaseUser.sub
  );

  if (!user) {
    throw new Error("User profile not found");
  }

  if (user.status !== "active") {
    throw new Error("Account is not active");
  }

  if (user.role !== "admin") {
    throw new Error("Admin access required");
  }

  return {
    firebaseUser,
    user,
  };
}

/* =========================================================
   Request Body
========================================================= */

async function getBody(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

/* =========================================================
   Generate ID
========================================================= */

function id(prefix = "") {
  const value =
    crypto.randomUUID().replaceAll("-", "");

  return prefix
    ? `${prefix}_${value}`
    : value;
}

/* =========================================================
   MAIN WORKER
========================================================= */

export default {
  async fetch(request, env) {
    const origin = corsOrigin(env);

    /* ---------- OPTIONS ---------- */

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Headers":
            "Content-Type, Authorization",
          "Access-Control-Allow-Methods":
            "GET, POST, PUT, PATCH, DELETE, OPTIONS",
        },
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      /* =====================================================
         ROOT
      ===================================================== */

      if (path === "/" && method === "GET") {
        return ok(
          {
            service: "Rajarhat Kamil Madrasha API",
            worker: "online",
            database: true,
            version: "1.0.0",
          },
          origin
        );
      }

      /* =====================================================
         HEALTH
      ===================================================== */

      if (path === "/api/health" && method === "GET") {
        let database = false;

        try {
          await env.DB
            .prepare("SELECT 1 AS ok")
            .first();

          database = true;
        } catch {
          database = false;
        }

        return ok(
          {
            worker: "online",
            database,
          },
          origin
        );
      }

      /* =====================================================
         PUBLIC SETTINGS
      ===================================================== */

      if (path === "/api/settings" && method === "GET") {
        const rows = await env.DB
          .prepare(
            `
            SELECT key, value
            FROM settings
            ORDER BY key
            `
          )
          .all();

        const settings = {};

        for (const row of rows.results || []) {
          settings[row.key] = row.value;
        }

        return ok({ settings }, origin);
      }

      /* =====================================================
         PUBLIC ACADEMIC YEARS
      ===================================================== */

      if (
        path === "/api/academic-years" &&
        method === "GET"
      ) {
        const rows = await env.DB
          .prepare(
            `
            SELECT *
            FROM academic_years
            ORDER BY year DESC
            `
          )
          .all();

        return ok(
          {
            academic_years: rows.results || [],
          },
          origin
        );
      }

      /* =====================================================
         PUBLIC CLASSES
      ===================================================== */

      if (
        path === "/api/classes" &&
        method === "GET"
      ) {
        const rows = await env.DB
          .prepare(
            `
            SELECT *
            FROM classes
            ORDER BY class_number ASC
            `
          )
          .all();

        return ok(
          {
            classes: rows.results || [],
          },
          origin
        );
      }

      /* =====================================================
         PUBLIC GROUPS
      ===================================================== */

      if (
        path === "/api/groups" &&
        method === "GET"
      ) {
        const rows = await env.DB
          .prepare(
            `
            SELECT *
            FROM groups
            ORDER BY name ASC
            `
          )
          .all();

        return ok(
          {
            groups: rows.results || [],
          },
          origin
        );
      }

      /* =====================================================
         PUBLIC SUBJECTS
      ===================================================== */

      if (
        path === "/api/subjects" &&
        method === "GET"
      ) {
        const rows = await env.DB
          .prepare(
            `
            SELECT *
            FROM subjects
            WHERE status = 'active'
            ORDER BY name ASC
            `
          )
          .all();

        return ok(
          {
            subjects: rows.results || [],
          },
          origin
        );
      }

      /* =====================================================
         PUBLIC TEACHERS
      ===================================================== */

      if (
        path === "/api/teachers" &&
        method === "GET"
      ) {
        const rows = await env.DB
          .prepare(
            `
            SELECT
              t.id,
              t.teacher_id,
              t.name,
              t.name_bn,
              t.designation,
              t.phone,
              t.email,
              t.qualification,
              t.address,
              t.photo_url,
              t.joining_date,
              t.employment_type,
              t.status,
              s.name AS subject_name,
              s.name_bn AS subject_name_bn
            FROM teachers t
            LEFT JOIN subjects s
              ON s.id = t.subject_id
            WHERE t.status = 'active'
            ORDER BY t.teacher_id ASC
            `
          )
          .all();

        return ok(
          {
            teachers: rows.results || [],
          },
          origin
        );
      }

      /* =====================================================
         PUBLIC EXAM TYPES
      ===================================================== */

      if (
        path === "/api/exam-types" &&
        method === "GET"
      ) {
        const rows = await env.DB
          .prepare(
            `
            SELECT *
            FROM exam_types
            WHERE status = 'active'
            ORDER BY name ASC
            `
          )
          .all();

        return ok(
          {
            exam_types: rows.results || [],
          },
          origin
        );
      }

      /* =====================================================
         PUBLIC NOTICES
      ===================================================== */

      if (
        path === "/api/notices" &&
        method === "GET"
      ) {
        const rows = await env.DB
          .prepare(
            `
            SELECT
              id,
              title,
              title_bn,
              content,
              content_bn,
              category,
              attachment_url,
              publish_at,
              expires_at,
              created_at
            FROM notices
            WHERE published = 1
              AND (
                publish_at IS NULL
                OR publish_at <= CURRENT_TIMESTAMP
              )
              AND (
                expires_at IS NULL
                OR expires_at > CURRENT_TIMESTAMP
              )
            ORDER BY
              COALESCE(publish_at, created_at) DESC
            `
          )
          .all();

        return ok(
          {
            notices: rows.results || [],
          },
          origin
        );
      }

      /* =====================================================
         PUBLIC HERO ADS
      ===================================================== */

      if (
        path === "/api/hero-ads" &&
        method === "GET"
      ) {
        const rows = await env.DB
          .prepare(
            `
            SELECT *
            FROM hero_ads
            WHERE status = 'active'
              AND (
                start_at IS NULL
                OR start_at <= CURRENT_TIMESTAMP
              )
              AND (
                end_at IS NULL
                OR end_at > CURRENT_TIMESTAMP
              )
            ORDER BY display_order ASC
            `
          )
          .all();

        return ok(
          {
            hero_ads: rows.results || [],
          },
          origin
        );
      }

      /* =====================================================
         PUBLIC EVENTS
      ===================================================== */

      if (
        path === "/api/events" &&
        method === "GET"
      ) {
        const rows = await env.DB
          .prepare(
            `
            SELECT *
            FROM events
            WHERE status = 'active'
            ORDER BY start_datetime ASC
            `
          )
          .all();

        return ok(
          {
            events: rows.results || [],
          },
          origin
        );
      }

      /* =====================================================
         PUBLIC GALLERY
      ===================================================== */

      if (
        path === "/api/gallery" &&
        method === "GET"
      ) {
        const rows = await env.DB
          .prepare(
            `
            SELECT
              id,
              title,
              description,
              image_url,
              category,
              display_order,
              created_at
            FROM gallery
            WHERE published = 1
            ORDER BY display_order ASC, created_at DESC
            `
          )
          .all();

        return ok(
          {
            gallery: rows.results || [],
          },
          origin
        );
      }

      /* =====================================================
         PUBLIC DOCUMENTS
      ===================================================== */

      if (
        path === "/api/documents" &&
        method === "GET"
      ) {
        const rows = await env.DB
          .prepare(
            `
            SELECT
              id,
              title,
              description,
              file_name,
              mime_type,
              file_size,
              category,
              created_at
            FROM documents
            WHERE visibility = 'public'
            ORDER BY created_at DESC
            `
          )
          .all();

        return ok(
          {
            documents: rows.results || [],
          },
          origin
        );
      }

      /* =====================================================
         PUBLIC RESULTS SEARCH
      ===================================================== */

      if (
        path === "/api/results" &&
        method === "GET"
      ) {
        const examId =
          url.searchParams.get("exam_id");

        const classId =
          url.searchParams.get("class_id");

        const roll =
          url.searchParams.get("roll");

        const name =
          url.searchParams.get("name");

        let sql = `
          SELECT
            m.*,
            e.name AS exam_name,
            e.name_bn AS exam_name_bn,
            c.name AS class_name,
            c.name_bn AS class_name_bn,
            g.name AS group_name,
            g.name_bn AS group_name_bn
          FROM marksheets m
          LEFT JOIN exams e
            ON e.id = m.exam_id
          LEFT JOIN classes c
            ON c.id = m.class_id
          LEFT JOIN groups g
            ON g.id = m.group_id
          WHERE m.published = 1
        `;

        const params = [];

        if (examId) {
          sql += ` AND m.exam_id = ?`;
          params.push(examId);
        }

        if (classId) {
          sql += ` AND m.class_id = ?`;
          params.push(classId);
        }

        if (roll) {
          sql += ` AND m.roll_number = ?`;
          params.push(Number(roll));
        }

        if (name) {
          sql += ` AND m.student_name LIKE ?`;
          params.push(`%${name}%`);
        }

        sql += `
          ORDER BY
            m.rank ASC,
            m.roll_number ASC
          LIMIT 100
        `;

        const rows = await env.DB
          .prepare(sql)
          .bind(...params)
          .all();

        return ok(
          {
            results: rows.results || [],
          },
          origin
        );
      }

      /* =====================================================
         AUTH - ME
      ===================================================== */

      if (
        path === "/api/me" &&
        method === "GET"
      ) {
        const firebaseUser =
          await requireAuth(request, env);

        const uid =
          firebaseUser.user_id ||
          firebaseUser.sub;

        const user =
          await getDbUser(env, uid);

        if (!user) {
          return error(
            "User profile not found. Please sync your account.",
            404,
            origin
          );
        }

        return ok(
          {
            user,
          },
          origin
        );
      }

      /* =====================================================
         AUTH - SYNC USER
         Firebase user → D1 users
      ===================================================== */

      if (
        path === "/api/auth/sync" &&
        method === "POST"
      ) {
        const firebaseUser =
          await requireAuth(request, env);

        const uid =
          firebaseUser.user_id ||
          firebaseUser.sub;

        const body = await getBody(request);

        const firebaseName =
          firebaseUser.name ||
          firebaseUser.firebase?.display_name ||
          body.name ||
          "User";

        const firebaseEmail =
          firebaseUser.email ||
          body.email ||
          null;

        const existing =
          await getDbUser(env, uid);

        if (existing) {
          await env.DB
            .prepare(
              `
              UPDATE users
              SET
                name = ?,
                email = ?,
                last_login_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
              WHERE firebase_uid = ?
              `
            )
            .bind(
              firebaseName,
              firebaseEmail,
              uid
            )
            .run();

          const user =
            await getDbUser(env, uid);

          return ok(
            {
              message: "User login synced",
              user,
            },
            origin
          );
        }

        const userId = id("user");

        await env.DB
          .prepare(
            `
            INSERT INTO users (
              id,
              firebase_uid,
              name,
              email,
              phone,
              photo_url,
              role,
              status,
              last_login_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'user', 'active', CURRENT_TIMESTAMP)
            `
          )
          .bind(
            userId,
            uid,
            firebaseName,
            firebaseEmail,
            body.phone || null,
            body.photo_url || null
          )
          .run();

        const user =
          await getDbUser(env, uid);

        return ok(
          {
            message: "User profile created",
            user,
          },
          origin
        );
      }

      /* =====================================================
         AUTH USER NOTIFICATIONS
      ===================================================== */

      if (
        path === "/api/notifications" &&
        method === "GET"
      ) {
        const firebaseUser =
          await requireAuth(request, env);

        const uid =
          firebaseUser.user_id ||
          firebaseUser.sub;

        const user =
          await getDbUser(env, uid);

        if (!user) {
          return error(
            "User profile not found",
            404,
            origin
          );
        }

        const rows = await env.DB
          .prepare(
            `
            SELECT *
            FROM notifications
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 100
            `
          )
          .bind(user.id)
          .all();

        return ok(
          {
            notifications: rows.results || [],
          },
          origin
        );
      }

      /* =====================================================
         MARK NOTIFICATION READ
      ===================================================== */

      if (
        path.match(
          /^\/api\/notifications\/[^/]+\/read$/
        ) &&
        method === "PATCH"
      ) {
        const firebaseUser =
          await requireAuth(request, env);

        const uid =
          firebaseUser.user_id ||
          firebaseUser.sub;

        const user =
          await getDbUser(env, uid);

        if (!user) {
          return error(
            "User profile not found",
            404,
            origin
          );
        }

        const notificationId =
          path.split("/")[3];

        await env.DB
          .prepare(
            `
            UPDATE notifications
            SET is_read = 1
            WHERE id = ?
              AND user_id = ?
            `
          )
          .bind(
            notificationId,
            user.id
          )
          .run();

        return ok(
          {
            message: "Notification marked as read",
          },
          origin
        );
      }

      /* =====================================================
         ADMIN - USERS
      ===================================================== */

      if (
        path === "/api/admin/users" &&
        method === "GET"
      ) {
        await requireAdmin(request, env);

        const rows = await env.DB
          .prepare(
            `
            SELECT
              id,
              firebase_uid,
              name,
              email,
              phone,
              photo_url,
              role,
              status,
              created_at,
              updated_at,
              last_login_at
            FROM users
            ORDER BY created_at DESC
            `
          )
          .all();

        return ok(
          {
            users: rows.results || [],
          },
          origin
        );
      }

      /* =====================================================
         ADMIN - CHANGE USER ROLE
      ===================================================== */

      if (
        path.match(/^\/api\/admin\/users\/[^/]+\/role$/) &&
        method === "PATCH"
      ) {
        const admin =
          await requireAdmin(request, env);

        const targetId =
          path.split("/")[4];

        const body = await getBody(request);

        const role = body.role;

        if (!["admin", "user"].includes(role)) {
          return error(
            "Invalid role",
            400,
            origin
          );
        }

        if (admin.user.id === targetId) {
          return error(
            "You cannot change your own role",
            400,
            origin
          );
        }

        await env.DB
          .prepare(
            `
            UPDATE users
            SET
              role = ?,
              updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            `
          )
          .bind(role, targetId)
          .run();

        return ok(
          {
            message: "User role updated",
          },
          origin
        );
      }

      /* =====================================================
         ADMIN - CHANGE USER STATUS
      ===================================================== */

      if (
        path.match(/^\/api\/admin\/users\/[^/]+\/status$/) &&
        method === "PATCH"
      ) {
        const admin =
          await requireAdmin(request, env);

        const targetId =
          path.split("/")[4];

        const body = await getBody(request);

        const status = body.status;

        if (
          !["active", "inactive", "suspended"]
            .includes(status)
        ) {
          return error(
            "Invalid status",
            400,
            origin
          );
        }

        if (admin.user.id === targetId) {
          return error(
            "You cannot change your own status",
            400,
            origin
          );
        }

        await env.DB
          .prepare(
            `
            UPDATE users
            SET
              status = ?,
              updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            `
          )
          .bind(status, targetId)
          .run();

        return ok(
          {
            message: "User status updated",
          },
          origin
        );
      }

      /* =====================================================
         ADMIN - SETTINGS UPDATE
      ===================================================== */

      if (
        path === "/api/admin/settings" &&
        method === "PUT"
      ) {
        const admin =
          await requireAdmin(request, env);

        const body = await getBody(request);

        if (!body || typeof body !== "object") {
          return error(
            "Invalid settings data",
            400,
            origin
          );
        }

        const statements = [];

        for (const [key, value] of Object.entries(body)) {
          statements.push(
            env.DB
              .prepare(
                `
                INSERT INTO settings (
                  key,
                  value,
                  updated_by,
                  updated_at
                )
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key)
                DO UPDATE SET
                  value = excluded.value,
                  updated_by = excluded.updated_by,
                  updated_at = CURRENT_TIMESTAMP
                `
              )
              .bind(
                key,
                value == null
                  ? null
                  : String(value),
                admin.user.id
              )
          );
        }

        if (statements.length > 0) {
          await env.DB.batch(statements);
        }

        return ok(
          {
            message: "Settings updated",
          },
          origin
        );
      }

      /* =====================================================
         ADMIN - CREATE NOTICE
      ===================================================== */

      if (
        path === "/api/admin/notices" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(request, env);

        const body = await getBody(request);

        if (!body.title || !body.content) {
          return error(
            "Title and content are required",
            400,
            origin
          );
        }

        const noticeId = id("notice");

        await env.DB
          .prepare(
            `
            INSERT INTO notices (
              id,
              title,
              title_bn,
              content,
              content_bn,
              category,
              attachment_url,
              published,
              publish_at,
              expires_at,
              created_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `
          )
          .bind(
            noticeId,
            body.title,
            body.title_bn || null,
            body.content,
            body.content_bn || null,
            body.category || "general",
            body.attachment_url || null,
            body.published ? 1 : 0,
            body.publish_at || null,
            body.expires_at || null,
            admin.user.id
          )
          .run();

        return ok(
          {
            message: "Notice created",
            id: noticeId,
          },
          origin
        );
      }

      /* =====================================================
         ADMIN - CREATE HERO AD
      ===================================================== */

      if (
        path === "/api/admin/hero-ads" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(request, env);

        const body = await getBody(request);

        if (!body.title) {
          return error(
            "Title is required",
            400,
            origin
          );
        }

        const heroId = id("hero");

        await env.DB
          .prepare(
            `
            INSERT INTO hero_ads (
              id,
              title,
              description,
              image_url,
              button_text,
              button_url,
              display_order,
              status,
              start_at,
              end_at,
              created_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `
          )
          .bind(
            heroId,
            body.title,
            body.description || null,
            body.image_url || null,
            body.button_text || null,
            body.button_url || null,
            Number(body.display_order || 0),
            body.status || "inactive",
            body.start_at || null,
            body.end_at || null,
            admin.user.id
          )
          .run();

        return ok(
          {
            message: "Hero ad created",
            id: heroId,
          },
          origin
        );
      }

      /* =====================================================
         ADMIN - CREATE GALLERY ITEM
      ===================================================== */

      if (
        path === "/api/admin/gallery" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(request, env);

        const body = await getBody(request);

        if (!body.image_url) {
          return error(
            "Image URL is required",
            400,
            origin
          );
        }

        const galleryId = id("gallery");

        await env.DB
          .prepare(
            `
            INSERT INTO gallery (
              id,
              title,
              description,
              image_url,
              category,
              display_order,
              published,
              uploaded_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `
          )
          .bind(
            galleryId,
            body.title || null,
            body.description || null,
            body.image_url,
            body.category || "general",
            Number(body.display_order || 0),
            body.published === false ? 0 : 1,
            admin.user.id
          )
          .run();

        return ok(
          {
            message: "Gallery item created",
            id: galleryId,
          },
          origin
        );
      }

      /* =====================================================
         ADMIN - CREATE TEACHER
      ===================================================== */

      if (
        path === "/api/admin/teachers" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(request, env);

        const body = await getBody(request);

        if (!body.name) {
          return error(
            "Teacher name is required",
            400,
            origin
          );
        }

        let teacherId = body.teacher_id;

        if (!teacherId) {
          const result =
            await env.DB
              .prepare(
                `
                SELECT teacher_id
                FROM teachers
                WHERE teacher_id LIKE 'RKM-%'
                ORDER BY teacher_id DESC
                LIMIT 1
                `
              )
              .first();

          let nextNumber = 1;

          if (result?.teacher_id) {
            const match =
              result.teacher_id.match(/RKM-(\d+)/);

            if (match) {
              nextNumber =
                Number(match[1]) + 1;
            }
          }

          teacherId =
            `RKM-${String(nextNumber).padStart(3, "0")}`;
        }

        const teacherDbId = id("teacher");

        await env.DB
          .prepare(
            `
            INSERT INTO teachers (
              id,
              teacher_id,
              name,
              name_bn,
              subject_id,
              designation,
              phone,
              email,
              qualification,
              address,
              photo_url,
              joining_date,
              employment_type,
              status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `
          )
          .bind(
            teacherDbId,
            teacherId,
            body.name,
            body.name_bn || null,
            body.subject_id || null,
            body.designation || null,
            body.phone || null,
            body.email || null,
            body.qualification || null,
            body.address || null,
            body.photo_url || null,
            body.joining_date || null,
            body.employment_type || null,
            body.status || "active"
          )
          .run();

        return ok(
          {
            message: "Teacher created",
            teacher_id: teacherId,
            id: teacherDbId,
          },
          origin
        );
      }

      /* =====================================================
         ADMIN - CREATE ACADEMIC YEAR
      ===================================================== */

      if (
        path === "/api/admin/academic-years" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(request, env);

        const body = await getBody(request);

        const year = Number(body.year);

        if (!Number.isInteger(year)) {
          return error(
            "Valid year is required",
            400,
            origin
          );
        }

        const yearId = id("year");

        await env.DB
          .prepare(
            `
            INSERT INTO academic_years (
              id,
              year,
              status,
              is_current
            )
            VALUES (?, ?, ?, ?)
            `
          )
          .bind(
            yearId,
            year,
            body.status || "upcoming",
            body.is_current ? 1 : 0
          )
          .run();

        return ok(
          {
            message: "Academic year created",
            id: yearId,
          },
          origin
        );
      }

      /* =====================================================
         ADMIN - CREATE CLASS
      ===================================================== */

      if (
        path === "/api/admin/classes" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(request, env);

        const body = await getBody(request);

        if (
          !Number.isInteger(
            Number(body.class_number)
          ) ||
          !body.name
        ) {
          return error(
            "class_number and name are required",
            400,
            origin
          );
        }

        const classId = id("class");

        await env.DB
          .prepare(
            `
            INSERT INTO classes (
              id,
              class_number,
              name,
              name_bn,
              status
            )
            VALUES (?, ?, ?, ?, ?)
            `
          )
          .bind(
            classId,
            Number(body.class_number),
            body.name,
            body.name_bn || null,
            body.status || "active"
          )
          .run();

        return ok(
          {
            message: "Class created",
            id: classId,
          },
          origin
        );
      }

      /* =====================================================
         ADMIN - CREATE SUBJECT
      ===================================================== */

      if (
        path === "/api/admin/subjects" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(request, env);

        const body = await getBody(request);

        if (!body.name) {
          return error(
            "Subject name is required",
            400,
            origin
          );
        }

        const subjectId = id("subject");

        await env.DB
          .prepare(
            `
            INSERT INTO subjects (
              id,
              name,
              name_bn,
              code,
              full_marks,
              pass_marks,
              status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            `
          )
          .bind(
            subjectId,
            body.name,
            body.name_bn || null,
            body.code || null,
            Number(body.full_marks ?? 100),
            Number(body.pass_marks ?? 33),
            body.status || "active"
          )
          .run();

        return ok(
          {
            message: "Subject created",
            id: subjectId,
          },
          origin
        );
      }

      /* =====================================================
         ADMIN - CREATE EXAM
      ===================================================== */

      if (
        path === "/api/admin/exams" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(request, env);

        const body = await getBody(request);

        if (
          !body.exam_type_id ||
          !body.name
        ) {
          return error(
            "exam_type_id and name are required",
            400,
            origin
          );
        }

        const examId = id("exam");

        await env.DB
          .prepare(
            `
            INSERT INTO exams (
              id,
              exam_type_id,
              name,
              name_bn,
              academic_year_id,
              class_id,
              group_id,
              start_date,
              end_date,
              status,
              published,
              created_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `
          )
          .bind(
            examId,
            body.exam_type_id,
            body.name,
            body.name_bn || null,
            body.academic_year_id || null,
            body.class_id || null,
            body.group_id || null,
            body.start_date || null,
            body.end_date || null,
            body.status || "upcoming",
            body.published ? 1 : 0,
            admin.user.id
          )
          .run();

        return ok(
          {
            message: "Exam created",
            id: examId,
          },
          origin
        );
      }

      /* =====================================================
         ADMIN - CREATE MARKSHEET
      ===================================================== */

      if (
        path === "/api/admin/marksheets" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(request, env);

        const body = await getBody(request);

        if (
          !body.exam_id ||
          !body.academic_year_id ||
          !body.class_id ||
          !body.student_name ||
          body.roll_number == null
        ) {
          return error(
            "exam_id, academic_year_id, class_id, student_name and roll_number are required",
            400,
            origin
          );
        }

        const marksheetId = id("marksheet");

        await env.DB
          .prepare(
            `
            INSERT INTO marksheets (
              id,
              exam_id,
              academic_year_id,
              class_id,
              group_id,
              student_name,
              roll_number,
              total_marks,
              percentage,
              grade,
              gpa,
              result_status,
              rank,
              published,
              created_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `
          )
          .bind(
            marksheetId,
            body.exam_id,
            body.academic_year_id,
            body.class_id,
            body.group_id || null,
            body.student_name,
            Number(body.roll_number),
            Number(body.total_marks || 0),
            Number(body.percentage || 0),
            body.grade || null,
            body.gpa == null
              ? null
              : Number(body.gpa),
            body.result_status || null,
            body.rank == null
              ? null
              : Number(body.rank),
            body.published ? 1 : 0,
            admin.user.id
          )
          .run();

        return ok(
          {
            message: "Marksheet created",
            id: marksheetId,
          },
          origin
        );
      }

      /* =====================================================
         ADMIN - CREATE MARKSHEET SUBJECT
      ===================================================== */

      if (
        path === "/api/admin/marksheet-subjects" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(request, env);

        const body = await getBody(request);

        if (
          !body.marksheet_id ||
          !body.subject_name
        ) {
          return error(
            "marksheet_id and subject_name are required",
            400,
            origin
          );
        }

        const subjectRowId =
          id("mark");

        await env.DB
          .prepare(
            `
            INSERT INTO marksheet_subjects (
              id,
              marksheet_id,
              subject_id,
              subject_name,
              full_marks,
              pass_marks,
              obtained_marks,
              grade,
              grade_point,
              remarks,
              display_order
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `
          )
          .bind(
            subjectRowId,
            body.marksheet_id,
            body.subject_id || null,
            body.subject_name,
            Number(body.full_marks || 100),
            Number(body.pass_marks || 33),
            Number(body.obtained_marks || 0),
            body.grade || null,
            body.grade_point == null
              ? null
              : Number(body.grade_point),
            body.remarks || null,
            Number(body.display_order || 0)
          )
          .run();

        return ok(
          {
            message: "Marksheet subject created",
            id: subjectRowId,
          },
          origin
        );
      }

      /* =====================================================
         ROUTE NOT FOUND
      ===================================================== */

      return error(
        "Route not found",
        404,
        origin
      );

    } catch (err) {
      console.error(err);

      return error(
        err?.message || "Internal server error",
        500,
        origin
      );
    }
  },
};
