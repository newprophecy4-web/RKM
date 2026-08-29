import { importX509, jwtVerify } from "jose";

/* =========================================================
   RAJARHAT KAMIL MADRASHA
   CLOUDFLARE WORKER API
   Firebase Authentication + Cloudflare D1 + Optional R2
========================================================= */

/* =========================================================
   RESPONSE HELPERS
========================================================= */

const json = (data, status = 200, origin = "*") => {
  return new Response(JSON.stringify(data), {
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
};

const ok = (data = {}, origin = "*") => {
  return json(
    {
      success: true,
      ...data,
    },
    200,
    origin
  );
};

const error = (message, status = 400, origin = "*") => {
  return json(
    {
      success: false,
      message,
    },
    status,
    origin
  );
};

const corsOrigin = (env) => {
  return env.CORS_ORIGIN || "*";
};

/* =========================================================
   ID
========================================================= */

function makeId(prefix = "") {
  const value = crypto.randomUUID().replaceAll("-", "");

  return prefix
    ? `${prefix}_${value}`
    : value;
}

/* =========================================================
   BODY
========================================================= */

async function getBody(request) {
  try {
    const body = await request.json();

    if (!body || typeof body !== "object") {
      return {};
    }

    return body;
  } catch {
    return {};
  }
}

/* =========================================================
   FIREBASE PUBLIC KEYS
========================================================= */

let firebaseKeys = null;
let firebaseKeysExpires = 0;

async function getFirebaseKeys() {
  const now = Date.now();

  if (
    firebaseKeys &&
    now < firebaseKeysExpires
  ) {
    return firebaseKeys;
  }

  const response = await fetch(
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
  );

  if (!response.ok) {
    throw new Error(
      "Unable to load Firebase public keys"
    );
  }

  firebaseKeys = await response.json();

  const cacheControl =
    response.headers.get("cache-control") || "";

  const match =
    cacheControl.match(/max-age=(\d+)/);

  const maxAge = match
    ? Number(match[1]) * 1000
    : 3600000;

  firebaseKeysExpires = now + maxAge;

  return firebaseKeys;
}

/* =========================================================
   BASE64URL DECODE
========================================================= */

function decodeBase64Url(value) {
  let str = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  while (str.length % 4) {
    str += "=";
  }

  return atob(str);
}

/* =========================================================
   FIREBASE TOKEN
========================================================= */

async function verifyFirebaseToken(
  token,
  projectId
) {
  if (!token) {
    throw new Error("Missing Firebase token");
  }

  if (!projectId) {
    throw new Error(
      "FIREBASE_PROJECT_ID is not configured"
    );
  }

  const parts = token.split(".");

  if (parts.length !== 3) {
    throw new Error("Invalid Firebase token");
  }

  let decoded;

  try {
    decoded = JSON.parse(
      decodeBase64Url(parts[0])
    );
  } catch {
    throw new Error("Invalid Firebase token header");
  }

  const kid = decoded.kid;

  if (!kid) {
    throw new Error(
      "Firebase token key ID missing"
    );
  }

  const keys = await getFirebaseKeys();

  if (!keys[kid]) {
    throw new Error(
      "Invalid Firebase token key"
    );
  }

  const publicKey = await importX509(
    keys[kid],
    "RS256"
  );

  const { payload } = await jwtVerify(
    token,
    publicKey,
    {
      algorithms: ["RS256"],
      issuer:
        `https://securetoken.google.com/${projectId}`,
      audience: projectId,
    }
  );

  if (
    !payload.sub ||
    payload.sub !== payload.user_id
  ) {
    throw new Error(
      "Invalid Firebase user"
    );
  }

  return payload;
}

/* =========================================================
   AUTH
========================================================= */

async function requireAuth(request, env) {
  const header =
    request.headers.get("Authorization");

  if (
    !header ||
    !header.startsWith("Bearer ")
  ) {
    throw new Error(
      "Authentication required"
    );
  }

  const token =
    header.substring(7).trim();

  return await verifyFirebaseToken(
    token,
    env.FIREBASE_PROJECT_ID
  );
}

/* =========================================================
   DB USER
========================================================= */

async function getDbUser(
  env,
  firebaseUid
) {
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
   ADMIN
========================================================= */

async function requireAdmin(
  request,
  env
) {
  const firebaseUser =
    await requireAuth(request, env);

  const uid =
    firebaseUser.user_id ||
    firebaseUser.sub;

  const user =
    await getDbUser(env, uid);

  if (!user) {
    throw new Error(
      "User profile not found"
    );
  }

  if (user.status !== "active") {
    throw new Error(
      "Account is not active"
    );
  }

  if (user.role !== "admin") {
    throw new Error(
      "Admin access required"
    );
  }

  return {
    firebaseUser,
    user,
  };
}

/* =========================================================
   ADMIN LOG
========================================================= */

async function adminLog(
  env,
  adminId,
  action,
  targetType = null,
  targetId = null,
  description = null
) {
  try {
    await env.DB
      .prepare(
        `
        INSERT INTO admin_logs (
          id,
          admin_user_id,
          action,
          target_type,
          target_id,
          description
        )
        VALUES (?, ?, ?, ?, ?, ?)
        `
      )
      .bind(
        makeId("log"),
        adminId,
        action,
        targetType,
        targetId,
        description
      )
      .run();
  } catch (err) {
    console.error(
      "Admin log error:",
      err
    );
  }
}

/* =========================================================
   INTEGER HELPER
========================================================= */

function integer(value) {
  const number = Number(value);

  return Number.isInteger(number)
    ? number
    : null;
}

/* =========================================================
   MAIN WORKER
========================================================= */

export default {
  async fetch(request, env) {
    const origin =
      corsOrigin(env);

    /* =====================================================
       CORS OPTIONS
    ===================================================== */

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin":
            origin,
          "Access-Control-Allow-Headers":
            "Content-Type, Authorization",
          "Access-Control-Allow-Methods":
            "GET, POST, PUT, PATCH, DELETE, OPTIONS",
        },
      });
    }

    const url =
      new URL(request.url);

    const path =
      url.pathname;

    const method =
      request.method;

    try {

      /* ===================================================
         ROOT
      =================================================== */

      if (
        path === "/" &&
        method === "GET"
      ) {
        return ok(
          {
            service:
              "Rajarhat Kamil Madrasha API",
            worker: "online",
            database: true,
            version: "2.0.0",
          },
          origin
        );
      }

      /* ===================================================
         HEALTH
      =================================================== */

      if (
        path === "/api/health" &&
        method === "GET"
      ) {
        let database = false;

        try {
          await env.DB
            .prepare(
              "SELECT 1 AS ok"
            )
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

      /* ===================================================
         PUBLIC SETTINGS
      =================================================== */

      if (
        path === "/api/settings" &&
        method === "GET"
      ) {
        const rows =
          await env.DB
            .prepare(
              `
              SELECT
                key,
                value,
                updated_at
              FROM settings
              ORDER BY key
              `
            )
            .all();

        const settings = {};

        for (
          const row of
          rows.results || []
        ) {
          settings[row.key] =
            row.value;
        }

        return ok(
          { settings },
          origin
        );
      }

      /* ===================================================
         PUBLIC ACADEMIC YEARS
      =================================================== */

      if (
        path === "/api/academic-years" &&
        method === "GET"
      ) {
        const rows =
          await env.DB
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
            academic_years:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         PUBLIC CLASSES
      =================================================== */

      if (
        path === "/api/classes" &&
        method === "GET"
      ) {
        const rows =
          await env.DB
            .prepare(
              `
              SELECT *
              FROM classes
              WHERE status = 'active'
              ORDER BY class_number ASC
              `
            )
            .all();

        return ok(
          {
            classes:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         PUBLIC GROUPS
      =================================================== */

      if (
        path === "/api/groups" &&
        method === "GET"
      ) {
        const rows =
          await env.DB
            .prepare(
              `
              SELECT *
              FROM groups
              WHERE status = 'active'
              ORDER BY name ASC
              `
            )
            .all();

        return ok(
          {
            groups:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         PUBLIC SUBJECTS
      =================================================== */

      if (
        path === "/api/subjects" &&
        method === "GET"
      ) {
        const rows =
          await env.DB
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
            subjects:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         PUBLIC CLASS SUBJECTS
      =================================================== */

      if (
        path === "/api/class-subjects" &&
        method === "GET"
      ) {
        const classId =
          url.searchParams.get(
            "class_id"
          );

        const groupId =
          url.searchParams.get(
            "group_id"
          );

        let sql = `
          SELECT
            cs.*,
            c.name AS class_name,
            c.name_bn AS class_name_bn,
            g.name AS group_name,
            g.name_bn AS group_name_bn,
            s.name AS subject_name,
            s.name_bn AS subject_name_bn,
            s.code AS subject_code
          FROM class_subjects cs
          LEFT JOIN classes c
            ON c.id = cs.class_id
          LEFT JOIN groups g
            ON g.id = cs.group_id
          LEFT JOIN subjects s
            ON s.id = cs.subject_id
          WHERE 1 = 1
        `;

        const params = [];

        if (classId) {
          sql +=
            " AND cs.class_id = ?";
          params.push(classId);
        }

        if (groupId) {
          sql +=
            " AND cs.group_id = ?";
          params.push(groupId);
        }

        sql +=
          " ORDER BY cs.display_order ASC, s.name ASC";

        const rows =
          await env.DB
            .prepare(sql)
            .bind(...params)
            .all();

        return ok(
          {
            class_subjects:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         PUBLIC TEACHERS
      =================================================== */

      if (
        path === "/api/teachers" &&
        method === "GET"
      ) {
        const rows =
          await env.DB
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
                t.subject_id,
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
            teachers:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         PUBLIC EXAM TYPES
      =================================================== */

      if (
        path === "/api/exam-types" &&
        method === "GET"
      ) {
        const rows =
          await env.DB
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
            exam_types:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         PUBLIC EXAMS
      =================================================== */

      if (
        path === "/api/exams" &&
        method === "GET"
      ) {
        const yearId =
          url.searchParams.get(
            "academic_year_id"
          );

        const classId =
          url.searchParams.get(
            "class_id"
          );

        const groupId =
          url.searchParams.get(
            "group_id"
          );

        let sql = `
          SELECT
            e.*,
            et.name AS exam_type_name,
            et.name_bn AS exam_type_name_bn,
            ay.year,
            c.name AS class_name,
            c.name_bn AS class_name_bn,
            g.name AS group_name,
            g.name_bn AS group_name_bn
          FROM exams e
          LEFT JOIN exam_types et
            ON et.id = e.exam_type_id
          LEFT JOIN academic_years ay
            ON ay.id = e.academic_year_id
          LEFT JOIN classes c
            ON c.id = e.class_id
          LEFT JOIN groups g
            ON g.id = e.group_id
          WHERE e.published = 1
        `;

        const params = [];

        if (yearId) {
          sql +=
            " AND e.academic_year_id = ?";
          params.push(yearId);
        }

        if (classId) {
          sql +=
            " AND e.class_id = ?";
          params.push(classId);
        }

        if (groupId) {
          sql +=
            " AND e.group_id = ?";
          params.push(groupId);
        }

        sql +=
          " ORDER BY e.start_date DESC, e.created_at DESC";

        const rows =
          await env.DB
            .prepare(sql)
            .bind(...params)
            .all();

        return ok(
          {
            exams:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         PUBLIC EXAM SUBJECTS
      =================================================== */

      if (
        path === "/api/exam-subjects" &&
        method === "GET"
      ) {
        const examId =
          url.searchParams.get(
            "exam_id"
          );

        let sql = `
          SELECT
            es.*,
            s.name AS subject_name,
            s.name_bn AS subject_name_bn,
            s.code AS subject_code
          FROM exam_subjects es
          LEFT JOIN subjects s
            ON s.id = es.subject_id
          WHERE 1 = 1
        `;

        const params = [];

        if (examId) {
          sql +=
            " AND es.exam_id = ?";
          params.push(examId);
        }

        sql +=
          " ORDER BY es.display_order ASC";

        const rows =
          await env.DB
            .prepare(sql)
            .bind(...params)
            .all();

        return ok(
          {
            exam_subjects:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         PUBLIC NOTICES
      =================================================== */

      if (
        path === "/api/notices" &&
        method === "GET"
      ) {
        const rows =
          await env.DB
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
                published,
                publish_at,
                expires_at,
                created_at,
                updated_at
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
                COALESCE(
                  publish_at,
                  created_at
                ) DESC
              `
            )
            .all();

        return ok(
          {
            notices:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         PUBLIC HERO ADS
      =================================================== */

      if (
        path === "/api/hero-ads" &&
        method === "GET"
      ) {
        const rows =
          await env.DB
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
            hero_ads:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         PUBLIC EVENTS
      =================================================== */

      if (
        path === "/api/events" &&
        method === "GET"
      ) {
        const rows =
          await env.DB
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
            events:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         PUBLIC GALLERY
      =================================================== */

      if (
        path === "/api/gallery" &&
        method === "GET"
      ) {
        const category =
          url.searchParams.get(
            "category"
          );

        let sql = `
          SELECT
            id,
            title,
            description,
            image_url,
            category,
            display_order,
            published,
            created_at
          FROM gallery
          WHERE published = 1
        `;

        const params = [];

        if (category) {
          sql +=
            " AND category = ?";
          params.push(category);
        }

        sql +=
          " ORDER BY display_order ASC, created_at DESC";

        const rows =
          await env.DB
            .prepare(sql)
            .bind(...params)
            .all();

        return ok(
          {
            gallery:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         PUBLIC DOCUMENTS
      =================================================== */

      if (
        path === "/api/documents" &&
        method === "GET"
      ) {
        const rows =
          await env.DB
            .prepare(
              `
              SELECT
                id,
                title,
                description,
                file_name,
                r2_key,
                mime_type,
                file_size,
                category,
                visibility,
                created_at
              FROM documents
              WHERE visibility = 'public'
              ORDER BY created_at DESC
              `
            )
            .all();

        return ok(
          {
            documents:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         PUBLIC GRADING SCALE
      =================================================== */

      if (
        path === "/api/grading-scale" &&
        method === "GET"
      ) {
        const rows =
          await env.DB
            .prepare(
              `
              SELECT *
              FROM grading_scales
              ORDER BY min_marks DESC
              `
            )
            .all();

        return ok(
          {
            grading_scale:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         PUBLIC RESULTS
      =================================================== */

      if (
        path === "/api/results" &&
        method === "GET"
      ) {
        const examId =
          url.searchParams.get(
            "exam_id"
          );

        const classId =
          url.searchParams.get(
            "class_id"
          );

        const yearId =
          url.searchParams.get(
            "academic_year_id"
          );

        const roll =
          url.searchParams.get(
            "roll"
          );

        const name =
          url.searchParams.get(
            "name"
          );

        const marksheetId =
          url.searchParams.get(
            "id"
          );

        let sql = `
          SELECT
            m.*,

            e.name AS exam_name,
            e.name_bn AS exam_name_bn,

            et.name AS exam_type_name,
            et.name_bn AS exam_type_name_bn,

            ay.year,

            c.name AS class_name,
            c.name_bn AS class_name_bn,

            g.name AS group_name,
            g.name_bn AS group_name_bn

          FROM marksheets m

          LEFT JOIN exams e
            ON e.id = m.exam_id

          LEFT JOIN exam_types et
            ON et.id = e.exam_type_id

          LEFT JOIN academic_years ay
            ON ay.id = m.academic_year_id

          LEFT JOIN classes c
            ON c.id = m.class_id

          LEFT JOIN groups g
            ON g.id = m.group_id

          WHERE m.published = 1
        `;

        const params = [];

        if (marksheetId) {
          sql +=
            " AND m.id = ?";
          params.push(marksheetId);
        }

        if (examId) {
          sql +=
            " AND m.exam_id = ?";
          params.push(examId);
        }

        if (classId) {
          sql +=
            " AND m.class_id = ?";
          params.push(classId);
        }

        if (yearId) {
          sql +=
            " AND m.academic_year_id = ?";
          params.push(yearId);
        }

        if (roll) {
          const rollNumber =
            integer(roll);

          if (rollNumber !== null) {
            sql +=
              " AND m.roll_number = ?";
            params.push(rollNumber);
          }
        }

        if (name) {
          sql +=
            " AND m.student_name LIKE ?";
          params.push(
            `%${name}%`
          );
        }

        sql += `
          ORDER BY
            CASE
              WHEN m.rank IS NULL THEN 999999
              ELSE m.rank
            END ASC,
            m.roll_number ASC
          LIMIT 100
        `;

        const rows =
          await env.DB
            .prepare(sql)
            .bind(...params)
            .all();

        const results =
          rows.results || [];

        /* Get subject marks */
        for (
          const result of results
        ) {
          const subjects =
            await env.DB
              .prepare(
                `
                SELECT *
                FROM marksheet_subjects
                WHERE marksheet_id = ?
                ORDER BY display_order ASC
                `
              )
              .bind(result.id)
              .all();

          result.subjects =
            subjects.results || [];

          const rank =
            await env.DB
              .prepare(
                `
                SELECT *
                FROM marksheet_ranks
                WHERE marksheet_id = ?
                LIMIT 1
                `
              )
              .bind(result.id)
              .first();

          result.manual_rank =
            rank || null;
        }

        return ok(
          { results },
          origin
        );
      }

      /* ===================================================
         AUTH ME
      =================================================== */

      if (
        path === "/api/me" &&
        method === "GET"
      ) {
        const firebaseUser =
          await requireAuth(
            request,
            env
          );

        const uid =
          firebaseUser.user_id ||
          firebaseUser.sub;

        const user =
          await getDbUser(
            env,
            uid
          );

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

      /* ===================================================
         AUTH SYNC
      =================================================== */

      if (
        path === "/api/auth/sync" &&
        method === "POST"
      ) {
        const firebaseUser =
          await requireAuth(
            request,
            env
          );

        const uid =
          firebaseUser.user_id ||
          firebaseUser.sub;

        const body =
          await getBody(request);

        const firebaseName =
          firebaseUser.name ||
          firebaseUser.firebase
            ?.display_name ||
          body.name ||
          "User";

        const firebaseEmail =
          firebaseUser.email ||
          body.email ||
          null;

        const existing =
          await getDbUser(
            env,
            uid
          );

        if (existing) {
          await env.DB
            .prepare(
              `
              UPDATE users
              SET
                name = ?,
                email = ?,
                last_login_at =
                  CURRENT_TIMESTAMP,
                updated_at =
                  CURRENT_TIMESTAMP
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
            await getDbUser(
              env,
              uid
            );

          return ok(
            {
              message:
                "User login synced",
              user,
            },
            origin
          );
        }

        const userId =
          makeId("user");

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
            VALUES (
              ?, ?, ?, ?, ?, ?,
              'user',
              'active',
              CURRENT_TIMESTAMP
            )
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
          await getDbUser(
            env,
            uid
          );

        return ok(
          {
            message:
              "User profile created",
            user,
          },
          origin
        );
      }

      /* ===================================================
         AUTH NOTIFICATIONS
      =================================================== */

      if (
        path === "/api/notifications" &&
        method === "GET"
      ) {
        const firebaseUser =
          await requireAuth(
            request,
            env
          );

        const uid =
          firebaseUser.user_id ||
          firebaseUser.sub;

        const user =
          await getDbUser(
            env,
            uid
          );

        if (!user) {
          return error(
            "User profile not found",
            404,
            origin
          );
        }

        const rows =
          await env.DB
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
            notifications:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         MARK NOTIFICATION READ
      =================================================== */

      if (
        path.match(
          /^\/api\/notifications\/[^/]+\/read$/
        ) &&
        method === "PATCH"
      ) {
        const firebaseUser =
          await requireAuth(
            request,
            env
          );

        const uid =
          firebaseUser.user_id ||
          firebaseUser.sub;

        const user =
          await getDbUser(
            env,
            uid
          );

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
            message:
              "Notification marked as read",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN USERS
      =================================================== */

      if (
        path === "/api/admin/users" &&
        method === "GET"
      ) {
        await requireAdmin(
          request,
          env
        );

        const rows =
          await env.DB
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
            users:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         ADMIN USER ROLE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/users\/[^/]+\/role$/
        ) &&
        method === "PATCH"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const targetId =
          path.split("/")[4];

        const body =
          await getBody(request);

        const role =
          body.role;

        if (
          !["admin", "user"]
            .includes(role)
        ) {
          return error(
            "Invalid role",
            400,
            origin
          );
        }

        if (
          admin.user.id === targetId
        ) {
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
              updated_at =
                CURRENT_TIMESTAMP
            WHERE id = ?
            `
          )
          .bind(
            role,
            targetId
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "change_user_role",
          "user",
          targetId,
          `Role changed to ${role}`
        );

        return ok(
          {
            message:
              "User role updated",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN USER STATUS
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/users\/[^/]+\/status$/
        ) &&
        method === "PATCH"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const targetId =
          path.split("/")[4];

        const body =
          await getBody(request);

        const status =
          body.status;

        if (
          ![
            "active",
            "inactive",
            "suspended",
          ].includes(status)
        ) {
          return error(
            "Invalid status",
            400,
            origin
          );
        }

        if (
          admin.user.id === targetId
        ) {
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
              updated_at =
                CURRENT_TIMESTAMP
            WHERE id = ?
            `
          )
          .bind(
            status,
            targetId
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "change_user_status",
          "user",
          targetId,
          `Status changed to ${status}`
        );

        return ok(
          {
            message:
              "User status updated",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN SETTINGS
      =================================================== */

      if (
        path === "/api/admin/settings" &&
        method === "PUT"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

        const statements = [];

        for (
          const [key, value]
          of Object.entries(body)
        ) {
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
                VALUES (
                  ?, ?, ?,
                  CURRENT_TIMESTAMP
                )
                ON CONFLICT(key)
                DO UPDATE SET
                  value =
                    excluded.value,
                  updated_by =
                    excluded.updated_by,
                  updated_at =
                    CURRENT_TIMESTAMP
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

        if (
          statements.length
        ) {
          await env.DB.batch(
            statements
          );
        }

        await adminLog(
          env,
          admin.user.id,
          "update_settings",
          "settings",
          null,
          "Website settings updated"
        );

        return ok(
          {
            message:
              "Settings updated",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN CREATE NOTICE
      =================================================== */

      if (
        path === "/api/admin/notices" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

        if (
          !body.title ||
          !body.content
        ) {
          return error(
            "Title and content are required",
            400,
            origin
          );
        }

        const noticeId =
          makeId("notice");

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
            VALUES (
              ?, ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?
            )
            `
          )
          .bind(
            noticeId,
            body.title,
            body.title_bn || null,
            body.content,
            body.content_bn || null,
            body.category ||
              "general",
            body.attachment_url ||
              null,
            body.published
              ? 1
              : 0,
            body.publish_at || null,
            body.expires_at || null,
            admin.user.id
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "create",
          "notice",
          noticeId,
          body.title
        );

        return ok(
          {
            message:
              "Notice created",
            id: noticeId,
          },
          origin
        );
      }

      /* ===================================================
         ADMIN UPDATE NOTICE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/notices\/[^/]+$/
        ) &&
        method === "PATCH"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const noticeId =
          path.split("/")[4];

        const body =
          await getBody(request);

        const existing =
          await env.DB
            .prepare(
              `
              SELECT *
              FROM notices
              WHERE id = ?
              `
            )
            .bind(noticeId)
            .first();

        if (!existing) {
          return error(
            "Notice not found",
            404,
            origin
          );
        }

        await env.DB
          .prepare(
            `
            UPDATE notices
            SET
              title = ?,
              title_bn = ?,
              content = ?,
              content_bn = ?,
              category = ?,
              attachment_url = ?,
              published = ?,
              publish_at = ?,
              expires_at = ?,
              updated_at =
                CURRENT_TIMESTAMP
            WHERE id = ?
            `
          )
          .bind(
            body.title ??
              existing.title,
            body.title_bn ??
              existing.title_bn,
            body.content ??
              existing.content,
            body.content_bn ??
              existing.content_bn,
            body.category ??
              existing.category,
            body.attachment_url ??
              existing.attachment_url,
            body.published == null
              ? existing.published
              : body.published
                ? 1
                : 0,
            body.publish_at ??
              existing.publish_at,
            body.expires_at ??
              existing.expires_at,
            noticeId
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "update",
          "notice",
          noticeId
        );

        return ok(
          {
            message:
              "Notice updated",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN DELETE NOTICE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/notices\/[^/]+$/
        ) &&
        method === "DELETE"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const noticeId =
          path.split("/")[4];

        await env.DB
          .prepare(
            `
            DELETE FROM notices
            WHERE id = ?
            `
          )
          .bind(noticeId)
          .run();

        await adminLog(
          env,
          admin.user.id,
          "delete",
          "notice",
          noticeId
        );

        return ok(
          {
            message:
              "Notice deleted",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN HERO AD
      =================================================== */

      if (
        path === "/api/admin/hero-ads" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

        if (!body.title) {
          return error(
            "Title is required",
            400,
            origin
          );
        }

        const heroId =
          makeId("hero");

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
            VALUES (
              ?, ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?
            )
            `
          )
          .bind(
            heroId,
            body.title,
            body.description || null,
            body.image_url || null,
            body.button_text || null,
            body.button_url || null,
            Number(
              body.display_order || 0
            ),
            body.status ||
              "inactive",
            body.start_at || null,
            body.end_at || null,
            admin.user.id
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "create",
          "hero_ad",
          heroId,
          body.title
        );

        return ok(
          {
            message:
              "Hero ad created",
            id: heroId,
          },
          origin
        );
      }

      /* ===================================================
         ADMIN UPDATE HERO AD
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/hero-ads\/[^/]+$/
        ) &&
        method === "PATCH"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const heroId =
          path.split("/")[4];

        const body =
          await getBody(request);

        const existing =
          await env.DB
            .prepare(
              `
              SELECT *
              FROM hero_ads
              WHERE id = ?
              `
            )
            .bind(heroId)
            .first();

        if (!existing) {
          return error(
            "Hero ad not found",
            404,
            origin
          );
        }

        await env.DB
          .prepare(
            `
            UPDATE hero_ads
            SET
              title = ?,
              description = ?,
              image_url = ?,
              button_text = ?,
              button_url = ?,
              display_order = ?,
              status = ?,
              start_at = ?,
              end_at = ?,
              updated_at =
                CURRENT_TIMESTAMP
            WHERE id = ?
            `
          )
          .bind(
            body.title ??
              existing.title,
            body.description ??
              existing.description,
            body.image_url ??
              existing.image_url,
            body.button_text ??
              existing.button_text,
            body.button_url ??
              existing.button_url,
            body.display_order ==
              null
              ? existing.display_order
              : Number(
                  body.display_order
                ),
            body.status ??
              existing.status,
            body.start_at ??
              existing.start_at,
            body.end_at ??
              existing.end_at,
            heroId
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "update",
          "hero_ad",
          heroId
        );

        return ok(
          {
            message:
              "Hero ad updated",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN DELETE HERO
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/hero-ads\/[^/]+$/
        ) &&
        method === "DELETE"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const heroId =
          path.split("/")[4];

        await env.DB
          .prepare(
            `
            DELETE FROM hero_ads
            WHERE id = ?
            `
          )
          .bind(heroId)
          .run();

        await adminLog(
          env,
          admin.user.id,
          "delete",
          "hero_ad",
          heroId
        );

        return ok(
          {
            message:
              "Hero ad deleted",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN GALLERY
      =================================================== */

      if (
        path === "/api/admin/gallery" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

        if (!body.image_url) {
          return error(
            "Image URL is required",
            400,
            origin
          );
        }

        const galleryId =
          makeId("gallery");

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
            VALUES (
              ?, ?, ?, ?, ?, ?, ?, ?
            )
            `
          )
          .bind(
            galleryId,
            body.title || null,
            body.description || null,
            body.image_url,
            body.category ||
              "general",
            Number(
              body.display_order || 0
            ),
            body.published === false
              ? 0
              : 1,
            admin.user.id
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "create",
          "gallery",
          galleryId
        );

        return ok(
          {
            message:
              "Gallery item created",
            id: galleryId,
          },
          origin
        );
      }

      /* ===================================================
         ADMIN UPDATE GALLERY
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/gallery\/[^/]+$/
        ) &&
        method === "PATCH"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const galleryId =
          path.split("/")[4];

        const body =
          await getBody(request);

        const existing =
          await env.DB
            .prepare(
              `
              SELECT *
              FROM gallery
              WHERE id = ?
              `
            )
            .bind(galleryId)
            .first();

        if (!existing) {
          return error(
            "Gallery item not found",
            404,
            origin
          );
        }

        await env.DB
          .prepare(
            `
            UPDATE gallery
            SET
              title = ?,
              description = ?,
              image_url = ?,
              category = ?,
              display_order = ?,
              published = ?
            WHERE id = ?
            `
          )
          .bind(
            body.title ??
              existing.title,
            body.description ??
              existing.description,
            body.image_url ??
              existing.image_url,
            body.category ??
              existing.category,
            body.display_order ==
              null
              ? existing.display_order
              : Number(
                  body.display_order
                ),
            body.published == null
              ? existing.published
              : body.published
                ? 1
                : 0,
            galleryId
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "update",
          "gallery",
          galleryId
        );

        return ok(
          {
            message:
              "Gallery item updated",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN DELETE GALLERY
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/gallery\/[^/]+$/
        ) &&
        method === "DELETE"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const galleryId =
          path.split("/")[4];

        await env.DB
          .prepare(
            `
            DELETE FROM gallery
            WHERE id = ?
            `
          )
          .bind(galleryId)
          .run();

        await adminLog(
          env,
          admin.user.id,
          "delete",
          "gallery",
          galleryId
        );

        return ok(
          {
            message:
              "Gallery item deleted",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN TEACHER CREATE
      =================================================== */

      if (
        path === "/api/admin/teachers" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

        if (!body.name) {
          return error(
            "Teacher name is required",
            400,
            origin
          );
        }

        let teacherId =
          body.teacher_id;

        if (!teacherId) {
          const result =
            await env.DB
              .prepare(
                `
                SELECT teacher_id
                FROM teachers
                WHERE teacher_id LIKE 'RKM-%'
                ORDER BY
                  CAST(
                    SUBSTR(
                      teacher_id,
                      5
                    ) AS INTEGER
                  ) DESC
                LIMIT 1
                `
              )
              .first();

          let nextNumber = 1;

          if (
            result?.teacher_id
          ) {
            const match =
              result.teacher_id.match(
                /^RKM-(\d+)$/
              );

            if (match) {
              nextNumber =
                Number(
                  match[1]
                ) + 1;
            }
          }

          teacherId =
            `RKM-${String(
              nextNumber
            ).padStart(3, "0")}`;
        }

        const teacherDbId =
          makeId("teacher");

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
            VALUES (
              ?, ?, ?, ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?, ?
            )
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
            body.employment_type ||
              null,
            body.status ||
              "active"
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "create",
          "teacher",
          teacherDbId,
          teacherId
        );

        return ok(
          {
            message:
              "Teacher created",
            teacher_id:
              teacherId,
            id:
              teacherDbId,
          },
          origin
        );
      }

      /* ===================================================
         ADMIN TEACHER UPDATE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/teachers\/[^/]+$/
        ) &&
        method === "PATCH"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const teacherDbId =
          path.split("/")[4];

        const body =
          await getBody(request);

        const existing =
          await env.DB
            .prepare(
              `
              SELECT *
              FROM teachers
              WHERE id = ?
              `
            )
            .bind(
              teacherDbId
            )
            .first();

        if (!existing) {
          return error(
            "Teacher not found",
            404,
            origin
          );
        }

        await env.DB
          .prepare(
            `
            UPDATE teachers
            SET
              teacher_id = ?,
              name = ?,
              name_bn = ?,
              subject_id = ?,
              designation = ?,
              phone = ?,
              email = ?,
              qualification = ?,
              address = ?,
              photo_url = ?,
              joining_date = ?,
              employment_type = ?,
              status = ?,
              updated_at =
                CURRENT_TIMESTAMP
            WHERE id = ?
            `
          )
          .bind(
            body.teacher_id ??
              existing.teacher_id,
            body.name ??
              existing.name,
            body.name_bn ??
              existing.name_bn,
            body.subject_id ??
              existing.subject_id,
            body.designation ??
              existing.designation,
            body.phone ??
              existing.phone,
            body.email ??
              existing.email,
            body.qualification ??
              existing.qualification,
            body.address ??
              existing.address,
            body.photo_url ??
              existing.photo_url,
            body.joining_date ??
              existing.joining_date,
            body.employment_type ??
              existing.employment_type,
            body.status ??
              existing.status,
            teacherDbId
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "update",
          "teacher",
          teacherDbId
        );

        return ok(
          {
            message:
              "Teacher updated",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN TEACHER DELETE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/teachers\/[^/]+$/
        ) &&
        method === "DELETE"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const teacherDbId =
          path.split("/")[4];

        await env.DB
          .prepare(
            `
            DELETE FROM teachers
            WHERE id = ?
            `
          )
          .bind(
            teacherDbId
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "delete",
          "teacher",
          teacherDbId
        );

        return ok(
          {
            message:
              "Teacher deleted",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN ACADEMIC YEAR CREATE
      =================================================== */

      if (
        path ===
          "/api/admin/academic-years" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

        const year =
          integer(body.year);

        if (year === null) {
          return error(
            "Valid year is required",
            400,
            origin
          );
        }

        const isCurrent =
          body.is_current
            ? 1
            : 0;

        if (isCurrent) {
          await env.DB
            .prepare(
              `
              UPDATE academic_years
              SET is_current = 0
              `
            )
            .run();
        }

        const yearId =
          makeId("year");

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
            body.status ||
              "upcoming",
            isCurrent
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "create",
          "academic_year",
          yearId,
          String(year)
        );

        return ok(
          {
            message:
              "Academic year created",
            id:
              yearId,
          },
          origin
        );
      }

      /* ===================================================
         ADMIN SET CURRENT YEAR
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/academic-years\/[^/]+\/current$/
        ) &&
        method === "PATCH"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const yearId =
          path.split("/")[4];

        await env.DB
          .prepare(
            `
            UPDATE academic_years
            SET is_current = 0
            `
          )
          .run();

        await env.DB
          .prepare(
            `
            UPDATE academic_years
            SET
              is_current = 1,
              status = 'active',
              updated_at =
                CURRENT_TIMESTAMP
            WHERE id = ?
            `
          )
          .bind(yearId)
          .run();

        await adminLog(
          env,
          admin.user.id,
          "set_current",
          "academic_year",
          yearId
        );

        return ok(
          {
            message:
              "Current academic year updated",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN CLASS CREATE
      =================================================== */

      if (
        path ===
          "/api/admin/classes" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

        const classNumber =
          integer(
            body.class_number
          );

        if (
          classNumber === null ||
          !body.name
        ) {
          return error(
            "class_number and name are required",
            400,
            origin
          );
        }

        const classId =
          makeId("class");

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
            classNumber,
            body.name,
            body.name_bn || null,
            body.status ||
              "active"
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "create",
          "class",
          classId,
          body.name
        );

        return ok(
          {
            message:
              "Class created",
            id:
              classId,
          },
          origin
        );
      }

      /* ===================================================
         ADMIN CLASS UPDATE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/classes\/[^/]+$/
        ) &&
        method === "PATCH"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const classId =
          path.split("/")[4];

        const body =
          await getBody(request);

        const existing =
          await env.DB
            .prepare(
              `
              SELECT *
              FROM classes
              WHERE id = ?
              `
            )
            .bind(classId)
            .first();

        if (!existing) {
          return error(
            "Class not found",
            404,
            origin
          );
        }

        await env.DB
          .prepare(
            `
            UPDATE classes
            SET
              class_number = ?,
              name = ?,
              name_bn = ?,
              status = ?,
              updated_at =
                CURRENT_TIMESTAMP
            WHERE id = ?
            `
          )
          .bind(
            body.class_number ==
              null
              ? existing.class_number
              : Number(
                  body.class_number
                ),
            body.name ??
              existing.name,
            body.name_bn ??
              existing.name_bn,
            body.status ??
              existing.status,
            classId
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "update",
          "class",
          classId
        );

        return ok(
          {
            message:
              "Class updated",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN CLASS DELETE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/classes\/[^/]+$/
        ) &&
        method === "DELETE"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const classId =
          path.split("/")[4];

        await env.DB
          .prepare(
            `
            DELETE FROM classes
            WHERE id = ?
            `
          )
          .bind(classId)
          .run();

        await adminLog(
          env,
          admin.user.id,
          "delete",
          "class",
          classId
        );

        return ok(
          {
            message:
              "Class deleted",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN SUBJECT CREATE
      =================================================== */

      if (
        path ===
          "/api/admin/subjects" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

        if (!body.name) {
          return error(
            "Subject name is required",
            400,
            origin
          );
        }

        const subjectId =
          makeId("subject");

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
            VALUES (
              ?, ?, ?, ?, ?, ?, ?
            )
            `
          )
          .bind(
            subjectId,
            body.name,
            body.name_bn || null,
            body.code || null,
            Number(
              body.full_marks ??
                100
            ),
            Number(
              body.pass_marks ??
                33
            ),
            body.status ||
              "active"
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "create",
          "subject",
          subjectId,
          body.name
        );

        return ok(
          {
            message:
              "Subject created",
            id:
              subjectId,
          },
          origin
        );
      }

      /* ===================================================
         ADMIN SUBJECT UPDATE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/subjects\/[^/]+$/
        ) &&
        method === "PATCH"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const subjectId =
          path.split("/")[4];

        const body =
          await getBody(request);

        const existing =
          await env.DB
            .prepare(
              `
              SELECT *
              FROM subjects
              WHERE id = ?
              `
            )
            .bind(subjectId)
            .first();

        if (!existing) {
          return error(
            "Subject not found",
            404,
            origin
          );
        }

        await env.DB
          .prepare(
            `
            UPDATE subjects
            SET
              name = ?,
              name_bn = ?,
              code = ?,
              full_marks = ?,
              pass_marks = ?,
              status = ?,
              updated_at =
                CURRENT_TIMESTAMP
            WHERE id = ?
            `
          )
          .bind(
            body.name ??
              existing.name,
            body.name_bn ??
              existing.name_bn,
            body.code ??
              existing.code,
            body.full_marks ==
              null
              ? existing.full_marks
              : Number(
                  body.full_marks
                ),
            body.pass_marks ==
              null
              ? existing.pass_marks
              : Number(
                  body.pass_marks
                ),
            body.status ??
              existing.status,
            subjectId
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "update",
          "subject",
          subjectId
        );

        return ok(
          {
            message:
              "Subject updated",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN SUBJECT DELETE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/subjects\/[^/]+$/
        ) &&
        method === "DELETE"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const subjectId =
          path.split("/")[4];

        await env.DB
          .prepare(
            `
            DELETE FROM subjects
            WHERE id = ?
            `
          )
          .bind(subjectId)
          .run();

        await adminLog(
          env,
          admin.user.id,
          "delete",
          "subject",
          subjectId
        );

        return ok(
          {
            message:
              "Subject deleted",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN CLASS SUBJECT CREATE
      =================================================== */

      if (
        path ===
          "/api/admin/class-subjects" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

        if (
          !body.class_id ||
          !body.subject_id
        ) {
          return error(
            "class_id and subject_id are required",
            400,
            origin
          );
        }

        const idValue =
          makeId("class_subject");

        await env.DB
          .prepare(
            `
            INSERT INTO class_subjects (
              id,
              class_id,
              group_id,
              subject_id,
              display_order
            )
            VALUES (?, ?, ?, ?, ?)
            `
          )
          .bind(
            idValue,
            body.class_id,
            body.group_id || null,
            body.subject_id,
            Number(
              body.display_order || 0
            )
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "create",
          "class_subject",
          idValue
        );

        return ok(
          {
            message:
              "Class subject created",
            id:
              idValue,
          },
          origin
        );
      }

      /* ===================================================
         ADMIN CLASS SUBJECT DELETE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/class-subjects\/[^/]+$/
        ) &&
        method === "DELETE"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const idValue =
          path.split("/")[4];

        await env.DB
          .prepare(
            `
            DELETE FROM class_subjects
            WHERE id = ?
            `
          )
          .bind(idValue)
          .run();

        await adminLog(
          env,
          admin.user.id,
          "delete",
          "class_subject",
          idValue
        );

        return ok(
          {
            message:
              "Class subject deleted",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN EXAM CREATE
      =================================================== */

      if (
        path ===
          "/api/admin/exams" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

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

        const examId =
          makeId("exam");

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
            VALUES (
              ?, ?, ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?
            )
            `
          )
          .bind(
            examId,
            body.exam_type_id,
            body.name,
            body.name_bn || null,
            body.academic_year_id ||
              null,
            body.class_id || null,
            body.group_id || null,
            body.start_date || null,
            body.end_date || null,
            body.status ||
              "upcoming",
            body.published
              ? 1
              : 0,
            admin.user.id
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "create",
          "exam",
          examId,
          body.name
        );

        return ok(
          {
            message:
              "Exam created",
            id:
              examId,
          },
          origin
        );
      }

      /* ===================================================
         ADMIN EXAM UPDATE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/exams\/[^/]+$/
        ) &&
        method === "PATCH"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const examId =
          path.split("/")[4];

        const body =
          await getBody(request);

        const existing =
          await env.DB
            .prepare(
              `
              SELECT *
              FROM exams
              WHERE id = ?
              `
            )
            .bind(examId)
            .first();

        if (!existing) {
          return error(
            "Exam not found",
            404,
            origin
          );
        }

        await env.DB
          .prepare(
            `
            UPDATE exams
            SET
              exam_type_id = ?,
              name = ?,
              name_bn = ?,
              academic_year_id = ?,
              class_id = ?,
              group_id = ?,
              start_date = ?,
              end_date = ?,
              status = ?,
              published = ?,
              updated_at =
                CURRENT_TIMESTAMP
            WHERE id = ?
            `
          )
          .bind(
            body.exam_type_id ??
              existing.exam_type_id,
            body.name ??
              existing.name,
            body.name_bn ??
              existing.name_bn,
            body.academic_year_id ??
              existing.academic_year_id,
            body.class_id ??
              existing.class_id,
            body.group_id ??
              existing.group_id,
            body.start_date ??
              existing.start_date,
            body.end_date ??
              existing.end_date,
            body.status ??
              existing.status,
            body.published == null
              ? existing.published
              : body.published
                ? 1
                : 0,
            examId
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "update",
          "exam",
          examId
        );

        return ok(
          {
            message:
              "Exam updated",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN EXAM DELETE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/exams\/[^/]+$/
        ) &&
        method === "DELETE"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const examId =
          path.split("/")[4];

        await env.DB
          .prepare(
            `
            DELETE FROM exams
            WHERE id = ?
            `
          )
          .bind(examId)
          .run();

        await adminLog(
          env,
          admin.user.id,
          "delete",
          "exam",
          examId
        );

        return ok(
          {
            message:
              "Exam deleted",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN EXAM SUBJECT
      =================================================== */

      if (
        path ===
          "/api/admin/exam-subjects" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

        if (
          !body.exam_id ||
          !body.subject_id
        ) {
          return error(
            "exam_id and subject_id are required",
            400,
            origin
          );
        }

        const idValue =
          makeId("exam_subject");

        await env.DB
          .prepare(
            `
            INSERT INTO exam_subjects (
              id,
              exam_id,
              subject_id,
              full_marks,
              pass_marks,
              exam_date,
              start_time,
              end_time,
              display_order
            )
            VALUES (
              ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            `
          )
          .bind(
            idValue,
            body.exam_id,
            body.subject_id,
            Number(
              body.full_marks ??
                100
            ),
            Number(
              body.pass_marks ??
                33
            ),
            body.exam_date ||
              null,
            body.start_time ||
              null,
            body.end_time ||
              null,
            Number(
              body.display_order ||
                0
            )
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "create",
          "exam_subject",
          idValue
        );

        return ok(
          {
            message:
              "Exam subject created",
            id:
              idValue,
          },
          origin
        );
      }

      /* ===================================================
         ADMIN EXAM SUBJECT DELETE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/exam-subjects\/[^/]+$/
        ) &&
        method === "DELETE"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const idValue =
          path.split("/")[4];

        await env.DB
          .prepare(
            `
            DELETE FROM exam_subjects
            WHERE id = ?
            `
          )
          .bind(idValue)
          .run();

        await adminLog(
          env,
          admin.user.id,
          "delete",
          "exam_subject",
          idValue
        );

        return ok(
          {
            message:
              "Exam subject deleted",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN MARKSHEET CREATE
      =================================================== */

      if (
        path ===
          "/api/admin/marksheets" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

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

        const rollNumber =
          integer(
            body.roll_number
          );

        if (
          rollNumber === null
        ) {
          return error(
            "roll_number must be an integer",
            400,
            origin
          );
        }

        const marksheetId =
          makeId("marksheet");

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
            VALUES (
              ?, ?, ?, ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?, ?, ?
            )
            `
          )
          .bind(
            marksheetId,
            body.exam_id,
            body.academic_year_id,
            body.class_id,
            body.group_id || null,
            body.student_name,
            rollNumber,
            Number(
              body.total_marks || 0
            ),
            Number(
              body.percentage || 0
            ),
            body.grade || null,
            body.gpa == null
              ? null
              : Number(body.gpa),
            body.result_status ||
              null,
            body.rank == null
              ? null
              : Number(body.rank),
            body.published
              ? 1
              : 0,
            admin.user.id
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "create",
          "marksheet",
          marksheetId,
          body.student_name
        );

        return ok(
          {
            message:
              "Marksheet created",
            id:
              marksheetId,
          },
          origin
        );
      }

      /* ===================================================
         ADMIN MARKSHEET UPDATE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/marksheets\/[^/]+$/
        ) &&
        method === "PATCH"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const marksheetId =
          path.split("/")[4];

        const body =
          await getBody(request);

        const existing =
          await env.DB
            .prepare(
              `
              SELECT *
              FROM marksheets
              WHERE id = ?
              `
            )
            .bind(
              marksheetId
            )
            .first();

        if (!existing) {
          return error(
            "Marksheet not found",
            404,
            origin
          );
        }

        await env.DB
          .prepare(
            `
            UPDATE marksheets
            SET
              exam_id = ?,
              academic_year_id = ?,
              class_id = ?,
              group_id = ?,
              student_name = ?,
              roll_number = ?,
              total_marks = ?,
              percentage = ?,
              grade = ?,
              gpa = ?,
              result_status = ?,
              rank = ?,
              published = ?,
              updated_at =
                CURRENT_TIMESTAMP
            WHERE id = ?
            `
          )
          .bind(
            body.exam_id ??
              existing.exam_id,
            body.academic_year_id ??
              existing.academic_year_id,
            body.class_id ??
              existing.class_id,
            body.group_id ??
              existing.group_id,
            body.student_name ??
              existing.student_name,
            body.roll_number ==
              null
              ? existing.roll_number
              : Number(
                  body.roll_number
                ),
            body.total_marks ==
              null
              ? existing.total_marks
              : Number(
                  body.total_marks
                ),
            body.percentage ==
              null
              ? existing.percentage
              : Number(
                  body.percentage
                ),
            body.grade ??
              existing.grade,
            body.gpa == null
              ? existing.gpa
              : Number(
                  body.gpa
                ),
            body.result_status ??
              existing.result_status,
            body.rank == null
              ? existing.rank
              : Number(
                  body.rank
                ),
            body.published == null
              ? existing.published
              : body.published
                ? 1
                : 0,
            marksheetId
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "update",
          "marksheet",
          marksheetId
        );

        return ok(
          {
            message:
              "Marksheet updated",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN MARKSHEET DELETE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/marksheets\/[^/]+$/
        ) &&
        method === "DELETE"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const marksheetId =
          path.split("/")[4];

        await env.DB
          .prepare(
            `
            DELETE FROM marksheets
            WHERE id = ?
            `
          )
          .bind(
            marksheetId
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "delete",
          "marksheet",
          marksheetId
        );

        return ok(
          {
            message:
              "Marksheet deleted",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN MARKSHEET SUBJECT CREATE
      =================================================== */

      if (
        path ===
          "/api/admin/marksheet-subjects" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

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
          makeId("mark");

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
            VALUES (
              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            `
          )
          .bind(
            subjectRowId,
            body.marksheet_id,
            body.subject_id || null,
            body.subject_name,
            Number(
              body.full_marks || 100
            ),
            Number(
              body.pass_marks || 33
            ),
            Number(
              body.obtained_marks || 0
            ),
            body.grade || null,
            body.grade_point == null
              ? null
              : Number(
                  body.grade_point
                ),
            body.remarks || null,
            Number(
              body.display_order || 0
            )
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "create",
          "marksheet_subject",
          subjectRowId
        );

        return ok(
          {
            message:
              "Marksheet subject created",
            id:
              subjectRowId,
          },
          origin
        );
      }

      /* ===================================================
         ADMIN MARKSHEET SUBJECT UPDATE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/marksheet-subjects\/[^/]+$/
        ) &&
        method === "PATCH"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const subjectRowId =
          path.split("/")[4];

        const body =
          await getBody(request);

        const existing =
          await env.DB
            .prepare(
              `
              SELECT *
              FROM marksheet_subjects
              WHERE id = ?
              `
            )
            .bind(
              subjectRowId
            )
            .first();

        if (!existing) {
          return error(
            "Marksheet subject not found",
            404,
            origin
          );
        }

        await env.DB
          .prepare(
            `
            UPDATE marksheet_subjects
            SET
              marksheet_id = ?,
              subject_id = ?,
              subject_name = ?,
              full_marks = ?,
              pass_marks = ?,
              obtained_marks = ?,
              grade = ?,
              grade_point = ?,
              remarks = ?,
              display_order = ?,
              updated_at =
                CURRENT_TIMESTAMP
            WHERE id = ?
            `
          )
          .bind(
            body.marksheet_id ??
              existing.marksheet_id,
            body.subject_id ??
              existing.subject_id,
            body.subject_name ??
              existing.subject_name,
            body.full_marks ==
              null
              ? existing.full_marks
              : Number(
                  body.full_marks
                ),
            body.pass_marks ==
              null
              ? existing.pass_marks
              : Number(
                  body.pass_marks
                ),
            body.obtained_marks ==
              null
              ? existing.obtained_marks
              : Number(
                  body.obtained_marks
                ),
            body.grade ??
              existing.grade,
            body.grade_point == null
              ? existing.grade_point
              : Number(
                  body.grade_point
                ),
            body.remarks ??
              existing.remarks,
            body.display_order ==
              null
              ? existing.display_order
              : Number(
                  body.display_order
                ),
            subjectRowId
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "update",
          "marksheet_subject",
          subjectRowId
        );

        return ok(
          {
            message:
              "Marksheet subject updated",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN MARKSHEET SUBJECT DELETE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/marksheet-subjects\/[^/]+$/
        ) &&
        method === "DELETE"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const subjectRowId =
          path.split("/")[4];

        await env.DB
          .prepare(
            `
            DELETE FROM marksheet_subjects
            WHERE id = ?
            `
          )
          .bind(
            subjectRowId
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "delete",
          "marksheet_subject",
          subjectRowId
        );

        return ok(
          {
            message:
              "Marksheet subject deleted",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN MANUAL RANK
      =================================================== */

      if (
        path ===
          "/api/admin/marksheet-ranks" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

        const rank =
          integer(
            body.rank_number
          );

        if (
          !body.marksheet_id ||
          rank === null ||
          rank < 1
        ) {
          return error(
            "marksheet_id and valid rank_number are required",
            400,
            origin
          );
        }

        const rankId =
          makeId("rank");

        await env.DB
          .prepare(
            `
            INSERT INTO marksheet_ranks (
              id,
              marksheet_id,
              rank_number,
              assigned_by
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(marksheet_id)
            DO UPDATE SET
              rank_number =
                excluded.rank_number,
              assigned_by =
                excluded.assigned_by,
              assigned_at =
                CURRENT_TIMESTAMP
            `
          )
          .bind(
            rankId,
            body.marksheet_id,
            rank,
            admin.user.id
          )
          .run();

        /*
          Keep marksheets.rank synchronized
          with manual rank table.
        */

        await env.DB
          .prepare(
            `
            UPDATE marksheets
            SET
              rank = ?,
              updated_at =
                CURRENT_TIMESTAMP
            WHERE id = ?
            `
          )
          .bind(
            rank,
            body.marksheet_id
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "assign_rank",
          "marksheet",
          body.marksheet_id,
          `Rank ${rank}`
        );

        return ok(
          {
            message:
              "Rank assigned",
            rank,
          },
          origin
        );
      }

      /* ===================================================
         ADMIN PROMOTION CREATE
      =================================================== */

      if (
        path ===
          "/api/admin/promotions" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

        const required = [
          "from_academic_year_id",
          "to_academic_year_id",
          "from_class_id",
          "to_class_id",
          "student_name",
          "previous_roll",
          "previous_rank",
          "new_roll",
        ];

        for (
          const field of required
        ) {
          if (
            body[field] == null ||
            body[field] === ""
          ) {
            return error(
              `${field} is required`,
              400,
              origin
            );
          }
        }

        const promotionId =
          makeId("promotion");

        await env.DB
          .prepare(
            `
            INSERT INTO promotions (
              id,
              from_academic_year_id,
              to_academic_year_id,
              from_class_id,
              to_class_id,
              group_id,
              student_name,
              previous_roll,
              previous_rank,
              new_roll,
              status,
              created_by
            )
            VALUES (
              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            `
          )
          .bind(
            promotionId,
            body.from_academic_year_id,
            body.to_academic_year_id,
            body.from_class_id,
            body.to_class_id,
            body.group_id || null,
            body.student_name,
            Number(
              body.previous_roll
            ),
            Number(
              body.previous_rank
            ),
            Number(
              body.new_roll
            ),
            body.status ||
              "promoted",
            admin.user.id
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "create",
          "promotion",
          promotionId,
          body.student_name
        );

        return ok(
          {
            message:
              "Promotion record created",
            id:
              promotionId,
          },
          origin
        );
      }

      /* ===================================================
         PUBLIC PROMOTIONS
      =================================================== */

      if (
        path === "/api/promotions" &&
        method === "GET"
      ) {
        const fromYear =
          url.searchParams.get(
            "from_academic_year_id"
          );

        const toYear =
          url.searchParams.get(
            "to_academic_year_id"
          );

        const classId =
          url.searchParams.get(
            "from_class_id"
          );

        let sql = `
          SELECT
            p.*,

            fy.year AS from_year,
            ty.year AS to_year,

            fc.name AS from_class_name,
            fc.name_bn AS from_class_name_bn,

            tc.name AS to_class_name,
            tc.name_bn AS to_class_name_bn,

            g.name AS group_name,
            g.name_bn AS group_name_bn

          FROM promotions p

          LEFT JOIN academic_years fy
            ON fy.id =
              p.from_academic_year_id

          LEFT JOIN academic_years ty
            ON ty.id =
              p.to_academic_year_id

          LEFT JOIN classes fc
            ON fc.id =
              p.from_class_id

          LEFT JOIN classes tc
            ON tc.id =
              p.to_class_id

          LEFT JOIN groups g
            ON g.id =
              p.group_id

          WHERE 1 = 1
        `;

        const params = [];

        if (fromYear) {
          sql +=
            " AND p.from_academic_year_id = ?";
          params.push(fromYear);
        }

        if (toYear) {
          sql +=
            " AND p.to_academic_year_id = ?";
          params.push(toYear);
        }

        if (classId) {
          sql +=
            " AND p.from_class_id = ?";
          params.push(classId);
        }

        sql +=
          " ORDER BY p.new_roll ASC";

        const rows =
          await env.DB
            .prepare(sql)
            .bind(...params)
            .all();

        return ok(
          {
            promotions:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         ADMIN EVENTS CREATE
      =================================================== */

      if (
        path ===
          "/api/admin/events" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

        if (
          !body.title ||
          !body.start_datetime
        ) {
          return error(
            "title and start_datetime are required",
            400,
            origin
          );
        }

        const eventId =
          makeId("event");

        await env.DB
          .prepare(
            `
            INSERT INTO events (
              id,
              title,
              description,
              event_type,
              start_datetime,
              end_datetime,
              location,
              image_url,
              status,
              created_by
            )
            VALUES (
              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            `
          )
          .bind(
            eventId,
            body.title,
            body.description || null,
            body.event_type ||
              "general",
            body.start_datetime,
            body.end_datetime ||
              null,
            body.location || null,
            body.image_url || null,
            body.status ||
              "active",
            admin.user.id
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "create",
          "event",
          eventId,
          body.title
        );

        return ok(
          {
            message:
              "Event created",
            id:
              eventId,
          },
          origin
        );
      }

      /* ===================================================
         ADMIN EVENTS UPDATE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/events\/[^/]+$/
        ) &&
        method === "PATCH"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const eventId =
          path.split("/")[4];

        const body =
          await getBody(request);

        const existing =
          await env.DB
            .prepare(
              `
              SELECT *
              FROM events
              WHERE id = ?
              `
            )
            .bind(eventId)
            .first();

        if (!existing) {
          return error(
            "Event not found",
            404,
            origin
          );
        }

        await env.DB
          .prepare(
            `
            UPDATE events
            SET
              title = ?,
              description = ?,
              event_type = ?,
              start_datetime = ?,
              end_datetime = ?,
              location = ?,
              image_url = ?,
              status = ?,
              updated_at =
                CURRENT_TIMESTAMP
            WHERE id = ?
            `
          )
          .bind(
            body.title ??
              existing.title,
            body.description ??
              existing.description,
            body.event_type ??
              existing.event_type,
            body.start_datetime ??
              existing.start_datetime,
            body.end_datetime ??
              existing.end_datetime,
            body.location ??
              existing.location,
            body.image_url ??
              existing.image_url,
            body.status ??
              existing.status,
            eventId
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "update",
          "event",
          eventId
        );

        return ok(
          {
            message:
              "Event updated",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN EVENTS DELETE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/events\/[^/]+$/
        ) &&
        method === "DELETE"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const eventId =
          path.split("/")[4];

        await env.DB
          .prepare(
            `
            DELETE FROM events
            WHERE id = ?
            `
          )
          .bind(eventId)
          .run();

        await adminLog(
          env,
          admin.user.id,
          "delete",
          "event",
          eventId
        );

        return ok(
          {
            message:
              "Event deleted",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN DOCUMENT CREATE
         R2 KEY ONLY
      =================================================== */

      if (
        path ===
          "/api/admin/documents" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

        if (
          !body.title ||
          !body.file_name ||
          !body.r2_key
        ) {
          return error(
            "title, file_name and r2_key are required",
            400,
            origin
          );
        }

        const documentId =
          makeId("document");

        await env.DB
          .prepare(
            `
            INSERT INTO documents (
              id,
              title,
              description,
              file_name,
              r2_key,
              mime_type,
              file_size,
              category,
              visibility,
              uploaded_by
            )
            VALUES (
              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            `
          )
          .bind(
            documentId,
            body.title,
            body.description || null,
            body.file_name,
            body.r2_key,
            body.mime_type || null,
            body.file_size == null
              ? null
              : Number(
                  body.file_size
                ),
            body.category ||
              "general",
            body.visibility ||
              "public",
            admin.user.id
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "create",
          "document",
          documentId,
          body.file_name
        );

        return ok(
          {
            message:
              "Document created",
            id:
              documentId,
          },
          origin
        );
      }

      /* ===================================================
         ADMIN DOCUMENT DELETE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/documents\/[^/]+$/
        ) &&
        method === "DELETE"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const documentId =
          path.split("/")[4];

        const document =
          await env.DB
            .prepare(
              `
              SELECT *
              FROM documents
              WHERE id = ?
              `
            )
            .bind(documentId)
            .first();

        if (!document) {
          return error(
            "Document not found",
            404,
            origin
          );
        }

        if (
          env.R2 &&
          document.r2_key
        ) {
          try {
            await env.R2.delete(
              document.r2_key
            );
          } catch (err) {
            console.error(
              "R2 delete failed:",
              err
            );
          }
        }

        await env.DB
          .prepare(
            `
            DELETE FROM documents
            WHERE id = ?
            `
          )
          .bind(documentId)
          .run();

        await adminLog(
          env,
          admin.user.id,
          "delete",
          "document",
          documentId
        );

        return ok(
          {
            message:
              "Document deleted",
          },
          origin
        );
      }

      /* ===================================================
         DOCUMENT DOWNLOAD
      =================================================== */

      if (
        path.match(
          /^\/api\/documents\/[^/]+\/download$/
        ) &&
        method === "GET"
      ) {
        const documentId =
          path.split("/")[3];

        const document =
          await env.DB
            .prepare(
              `
              SELECT *
              FROM documents
              WHERE id = ?
              LIMIT 1
              `
            )
            .bind(documentId)
            .first();

        if (!document) {
          return error(
            "Document not found",
            404,
            origin
          );
        }

        if (
          document.visibility !==
          "public"
        ) {
          try {
            await requireAuth(
              request,
              env
            );
          } catch {
            return error(
              "Authentication required",
              401,
              origin
            );
          }

          if (
            document.visibility ===
            "admin"
          ) {
            try {
              await requireAdmin(
                request,
                env
              );
            } catch {
              return error(
                "Admin access required",
                403,
                origin
              );
            }
          }
        }

        if (
          !env.R2 ||
          !document.r2_key
        ) {
          return error(
            "R2 document storage is not configured",
            503,
            origin
          );
        }

        const object =
          await env.R2.get(
            document.r2_key
          );

        if (!object) {
          return error(
            "File not found in R2",
            404,
            origin
          );
        }

        const headers =
          new Headers();

        object.writeHttpMetadata(
          headers
        );

        headers.set(
          "Access-Control-Allow-Origin",
          origin
        );

        headers.set(
          "Content-Disposition",
          `inline; filename="${encodeURIComponent(
            document.file_name
          )}"`
        );

        return new Response(
          object.body,
          {
            headers,
          }
        );
      }

      /* ===================================================
         ADMIN CREATE NOTIFICATION
      =================================================== */

      if (
        path ===
          "/api/admin/notifications" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

        if (
          !body.user_id ||
          !body.title ||
          !body.message
        ) {
          return error(
            "user_id, title and message are required",
            400,
            origin
          );
        }

        const notificationId =
          makeId("notification");

        await env.DB
          .prepare(
            `
            INSERT INTO notifications (
              id,
              user_id,
              title,
              message,
              type,
              reference_type,
              reference_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            `
          )
          .bind(
            notificationId,
            body.user_id,
            body.title,
            body.message,
            body.type ||
              "general",
            body.reference_type ||
              null,
            body.reference_id ||
              null
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "create",
          "notification",
          notificationId
        );

        return ok(
          {
            message:
              "Notification created",
            id:
              notificationId,
          },
          origin
        );
      }

      /* ===================================================
         ADMIN GRADING SCALE CREATE
      =================================================== */

      if (
        path ===
          "/api/admin/grading-scale" &&
        method === "POST"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const body =
          await getBody(request);

        if (
          body.min_marks == null ||
          body.max_marks == null ||
          !body.grade ||
          body.grade_point == null
        ) {
          return error(
            "min_marks, max_marks, grade and grade_point are required",
            400,
            origin
          );
        }

        const gradingId =
          makeId("grade");

        await env.DB
          .prepare(
            `
            INSERT INTO grading_scales (
              id,
              min_marks,
              max_marks,
              grade,
              grade_point,
              description
            )
            VALUES (?, ?, ?, ?, ?, ?)
            `
          )
          .bind(
            gradingId,
            Number(
              body.min_marks
            ),
            Number(
              body.max_marks
            ),
            body.grade,
            Number(
              body.grade_point
            ),
            body.description ||
              null
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "create",
          "grading_scale",
          gradingId
        );

        return ok(
          {
            message:
              "Grading scale created",
            id:
              gradingId,
          },
          origin
        );
      }

      /* ===================================================
         ADMIN GRADING SCALE DELETE
      =================================================== */

      if (
        path.match(
          /^\/api\/admin\/grading-scale\/[^/]+$/
        ) &&
        method === "DELETE"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const gradingId =
          path.split("/")[4];

        await env.DB
          .prepare(
            `
            DELETE FROM grading_scales
            WHERE id = ?
            `
          )
          .bind(
            gradingId
          )
          .run();

        await adminLog(
          env,
          admin.user.id,
          "delete",
          "grading_scale",
          gradingId
        );

        return ok(
          {
            message:
              "Grading scale deleted",
          },
          origin
        );
      }

      /* ===================================================
         ADMIN LOGS
      =================================================== */

      if (
        path ===
          "/api/admin/logs" &&
        method === "GET"
      ) {
        const admin =
          await requireAdmin(
            request,
            env
          );

        const limit =
          Math.min(
            Number(
              url.searchParams.get(
                "limit"
              ) || 100
            ),
            500
          );

        const rows =
          await env.DB
            .prepare(
              `
              SELECT
                l.*,
                u.name AS admin_name,
                u.email AS admin_email
              FROM admin_logs l
              LEFT JOIN users u
                ON u.id =
                  l.admin_user_id
              ORDER BY
                l.created_at DESC
              LIMIT ?
              `
            )
            .bind(limit)
            .all();

        return ok(
          {
            logs:
              rows.results || [],
          },
          origin
        );
      }

      /* ===================================================
         ADMIN DASHBOARD STATS
      =================================================== */

      if (
        path ===
          "/api/admin/dashboard" &&
        method === "GET"
      ) {
        await requireAdmin(
          request,
          env
        );

        const tables = [
          "users",
          "teachers",
          "classes",
          "subjects",
          "exams",
          "marksheets",
          "notices",
          "gallery",
          "events",
          "documents",
        ];

        const stats = {};

        for (
          const table of tables
        ) {
          const row =
            await env.DB
              .prepare(
                `SELECT COUNT(*) AS count FROM ${table}`
              )
              .first();

          stats[table] =
            Number(
              row?.count || 0
            );
        }

        return ok(
          { stats },
          origin
        );
      }

      /* ===================================================
         ROUTE NOT FOUND
      =================================================== */

      return error(
        "Route not found",
        404,
        origin
      );

    } catch (err) {
      console.error(
        "Worker error:",
        err
      );

      const message =
        err?.message ||
        "Internal server error";

      let status = 500;

      if (
        message.includes(
          "Authentication required"
        ) ||
        message.includes(
          "Missing Firebase token"
        ) ||
        message.includes(
          "Invalid Firebase token"
        )
      ) {
        status = 401;
      }

      if (
        message.includes(
          "Admin access required"
        )
      ) {
        status = 403;
      }

      return error(
        message,
        status,
        origin
      );
    }
  },
};
