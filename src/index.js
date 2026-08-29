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
          await requireAdminrequireAdmin
