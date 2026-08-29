import { jwtVerify, createRemoteJWKSet } from "jose";

/*
=========================================================
RAJARHAT KAMIL MADRASHA
CLOUDFLARE WORKER API V2

Firebase Authentication
Cloudflare D1
ImgBB image URLs
Optional R2 documents

API BASE:
https://rkm.newprophecy4.workers.dev
=========================================================
*/


const PROJECT_ID = "rkm-2026-969da";

const FIREBASE_ISSUER =
  `https://securetoken.google.com/${PROJECT_ID}`;

const FIREBASE_KEYS =
  createRemoteJWKSet(
    new URL(
      "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
    )
  );


/* =======================================================
   RESPONSE HELPERS
======================================================= */

function json(data, status = 200, request = null) {
  const origin = request?.headers.get("Origin") || "*";

  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",

        "Access-Control-Allow-Origin": origin,

        "Access-Control-Allow-Headers":
          "Content-Type, Authorization",

        "Access-Control-Allow-Methods":
          "GET, POST, PUT, PATCH, DELETE, OPTIONS",

        "Access-Control-Allow-Credentials":
          "true",

        "Cache-Control":
          "no-store"
      }
    }
  );
}


function ok(data, request) {
  return json(
    {
      success: true,
      ...data
    },
    200,
    request
  );
}


function error(message, status = 400, request) {
  return json(
    {
      success: false,
      error: message
    },
    status,
    request
  );
}


function options(request) {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin":
        request.headers.get("Origin") || "*",

      "Access-Control-Allow-Headers":
        "Content-Type, Authorization",

      "Access-Control-Allow-Methods":
        "GET, POST, PUT, PATCH, DELETE, OPTIONS",

      "Access-Control-Allow-Credentials":
        "true"
    }
  });
}


/* =======================================================
   UTILS
======================================================= */

function id(prefix = "id") {
  return `${prefix}_${crypto.randomUUID()}`;
}


function now() {
  return new Date().toISOString();
}


async function body(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}


function cleanNumber(value, fallback = 0) {
  const n = Number(value);

  return Number.isFinite(n)
    ? n
    : fallback;
}


function bool(value) {
  return value === true ||
         value === 1 ||
         value === "1" ||
         value === "true";
}


/* =======================================================
   FIREBASE AUTH
======================================================= */

async function verifyFirebaseToken(token) {

  if (!token) {
    throw new Error("Missing Firebase token");
  }

  const { payload } = await jwtVerify(
    token,
    FIREBASE_KEYS,
    {
      issuer: FIREBASE_ISSUER,
      audience: PROJECT_ID
    }
  );

  if (!payload.sub) {
    throw new Error("Invalid Firebase token");
  }

  return payload;
}


function getBearer(request) {

  const header =
    request.headers.get("Authorization");

  if (!header) {
    return null;
  }

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.substring(7);
}


/* =======================================================
   CURRENT USER
======================================================= */

async function authenticate(request, env) {

  const token =
    getBearer(request);

  if (!token) {
    throw new Error("Authentication required");
  }

  const firebase =
    await verifyFirebaseToken(token);

  const uid =
    firebase.sub;

  const user =
    await env.DB.prepare(
      `
      SELECT *
      FROM users
      WHERE firebase_uid = ?
      LIMIT 1
      `
    )
    .bind(uid)
    .first();

  if (!user) {

    throw new Error(
      "User profile not found. Call /api/auth/sync first."
    );

  }

  if (user.status !== "active") {
    throw new Error("Account is not active");
  }

  return {
    firebase,
    user
  };
}


async function requireAdmin(request, env) {

  const auth =
    await authenticate(request, env);

  if (auth.user.role !== "admin") {
    throw new Error("Admin access required");
  }

  return auth;
}


/* =======================================================
   ADMIN LOG
======================================================= */

async function logAdmin(
  env,
  adminId,
  action,
  targetType = null,
  targetId = null,
  description = null
) {

  await env.DB.prepare(
    `
    INSERT INTO admin_logs
    (
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
    id("log"),
    adminId,
    action,
    targetType,
    targetId,
    description
  )
  .run();
}


/* =======================================================
   GRADE CALCULATION
======================================================= */

function gradeFor(marks) {

  if (marks >= 80)
    return ["A+", 5.00];

  if (marks >= 70)
    return ["A", 4.00];

  if (marks >= 60)
    return ["A-", 3.50];

  if (marks >= 50)
    return ["B", 3.00];

  if (marks >= 40)
    return ["C", 2.00];

  if (marks >= 33)
    return ["D", 1.00];

  return ["F", 0.00];
}


function resultFor(marks, passMarks) {

  return marks >= passMarks
    ? "Pass"
    : "Fail";
}


/* =======================================================
   CALCULATE MARKSHEET
======================================================= */

async function calculateMarksheet(
  env,
  marksheetId
) {

  const rows =
    await env.DB.prepare(
      `
      SELECT
        marks,
        full_marks,
        pass_marks
      FROM marksheet_subjects
      WHERE marksheet_id = ?
      `
    )
    .bind(marksheetId)
    .all();

  const subjects =
    rows.results || [];

  if (!subjects.length) {

    await env.DB.prepare(
      `
      UPDATE marksheets
      SET
        total_marks = 0,
        average_marks = 0,
        percentage = 0,
        grade = NULL,
        grade_point = NULL,
        result_status = NULL,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
      `
    )
    .bind(marksheetId)
    .run();

    return;
  }


  let total = 0;
  let totalFull = 0;
  let failed = false;

  for (const s of subjects) {

    const marks =
      cleanNumber(s.marks);

    const full =
      cleanNumber(s.full_marks, 100);

    const pass =
      cleanNumber(s.pass_marks, 33);

    total += marks;
    totalFull += full;

    if (marks < pass) {
      failed = true;
    }
  }


  const percentage =
    totalFull > 0
      ? (total / totalFull) * 100
      : 0;


  const average =
    subjects.length > 0
      ? total / subjects.length
      : 0;


  const [grade, gradePoint] =
    gradeFor(percentage);


  const status =
    failed ? "Fail" : "Pass";


  await env.DB.prepare(
    `
    UPDATE marksheets
    SET
      total_marks = ?,
      average_marks = ?,
      percentage = ?,
      grade = ?,
      grade_point = ?,
      result_status = ?,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    `
  )
  .bind(
    total,
    average,
    percentage,
    grade,
    gradePoint,
    status,
    marksheetId
  )
  .run();
}


/* =======================================================
   ROOT
======================================================= */

async function root(request) {

  return ok(
    {
      name:
        "Rajarhat Kamil Madrasha API",

      version:
        "2.0.0",

      status:
        "running",

      authentication:
        "Firebase Authentication",

      database:
        "Cloudflare D1"
    },
    request
  );
}


/* =======================================================
   HEALTH
======================================================= */

async function health(request, env) {

  try {

    await env.DB
      .prepare("SELECT 1 AS ok")
      .first();

    return ok(
      {
        api: "ok",
        database: "ok",
        time: now()
      },
      request
    );

  } catch (e) {

    return error(
      "Database connection failed",
      500,
      request
    );

  }
}


/* =======================================================
   SETTINGS
======================================================= */

async function getSettings(request, env) {

  const rows =
    await env.DB.prepare(
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

  return ok({ settings }, request);
}


async function updateSettings(
  request,
  env,
  auth
) {

  const data =
    await body(request);

  for (const [key, value] of Object.entries(data)) {

    await env.DB.prepare(
      `
      INSERT INTO settings
      (
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
      String(value ?? ""),
      auth.user.id
    )
    .run();
  }


  await logAdmin(
    env,
    auth.user.id,
    "UPDATE_SETTINGS",
    "settings",
    null,
    "Website settings updated"
  );


  return ok(
    {
      message: "Settings updated"
    },
    request
  );
}


/* =======================================================
   ACADEMIC YEARS
======================================================= */

async function getAcademicYears(
  request,
  env
) {

  const rows =
    await env.DB.prepare(
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
        rows.results || []
    },
    request
  );
}


async function createAcademicYear(
  request,
  env,
  auth
) {

  const data =
    await body(request);

  const year =
    cleanNumber(data.year);

  if (!year) {
    return error(
      "year is required",
      400,
      request
    );
  }

  const yearId =
    id("year");


  try {

    await env.DB.prepare(
      `
      INSERT INTO academic_years
      (
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
      data.status || "upcoming",
      bool(data.is_current) ? 1 : 0
    )
    .run();


    if (bool(data.is_current)) {

      await env.DB.prepare(
        `
        UPDATE academic_years
        SET is_current = 0,
            status =
              CASE
                WHEN status = 'active'
                THEN 'completed'
                ELSE status
              END
        WHERE id != ?
        `
      )
      .bind(yearId)
      .run();

      await env.DB.prepare(
        `
        UPDATE academic_years
        SET status = 'active'
        WHERE id = ?
        `
      )
      .bind(yearId)
      .run();
    }


    await logAdmin(
      env,
      auth.user.id,
      "CREATE_ACADEMIC_YEAR",
      "academic_year",
      yearId,
      `Academic year ${year} created`
    );


    return ok(
      {
        id: yearId,
        message: "Academic year created"
      },
      request
    );

  } catch (e) {

    return error(
      e.message,
      400,
      request
    );

  }
}


/* =======================================================
   CLASSES
======================================================= */

async function getClasses(
  request,
  env
) {

  const rows =
    await env.DB.prepare(
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
        rows.results || []
    },
    request
  );
}


async function createClass(
  request,
  env,
  auth
) {

  const data =
    await body(request);

  const classNumber =
    cleanNumber(data.class_number);

  if (
    classNumber < 1 ||
    classNumber > 10
  ) {

    return error(
      "class_number must be 1-10",
      400,
      request
    );
  }


  const classId =
    id("class");


  try {

    await env.DB.prepare(
      `
      INSERT INTO classes
      (
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
      data.name || `Class ${classNumber}`,
      data.name_bn || null,
      data.status || "active"
    )
    .run();


    await logAdmin(
      env,
      auth.user.id,
      "CREATE_CLASS",
      "class",
      classId,
      `Class ${classNumber} created`
    );


    return ok(
      {
        id: classId,
        message: "Class created"
      },
      request
    );

  } catch (e) {

    return error(
      e.message,
      400,
      request
    );

  }
}


/* =======================================================
   GROUPS
======================================================= */

async function getGroups(
  request,
  env
) {

  const rows =
    await env.DB.prepare(
      `
      SELECT *
      FROM groups
      WHERE status = 'active'
      ORDER BY name
      `
    )
    .all();

  return ok(
    {
      groups:
        rows.results || []
    },
    request
  );
}


/* =======================================================
   SUBJECTS
======================================================= */

async function getSubjects(
  request,
  env
) {

  const rows =
    await env.DB.prepare(
      `
      SELECT *
      FROM subjects
      WHERE status = 'active'
      ORDER BY name
      `
    )
    .all();

  return ok(
    {
      subjects:
        rows.results || []
    },
    request
  );
}


async function createSubject(
  request,
  env,
  auth
) {

  const data =
    await body(request);

  if (!data.name) {

    return error(
      "Subject name is required",
      400,
      request
    );
  }


  const subjectId =
    id("subject");


  try {

    await env.DB.prepare(
      `
      INSERT INTO subjects
      (
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
      data.name,
      data.name_bn || null,
      data.code || null,
      cleanNumber(data.full_marks, 100),
      cleanNumber(data.pass_marks, 33),
      data.status || "active"
    )
    .run();


    await logAdmin(
      env,
      auth.user.id,
      "CREATE_SUBJECT",
      "subject",
      subjectId,
      data.name
    );


    return ok(
      {
        id: subjectId,
        message: "Subject created"
      },
      request
    );

  } catch (e) {

    return error(
      e.message,
      400,
      request
    );

  }
}


/* =======================================================
   TEACHERS
======================================================= */

async function generateTeacherId(env) {

  const row =
    await env.DB.prepare(
      `
      SELECT teacher_id
      FROM teachers
      WHERE teacher_id LIKE 'RKM-%'
      ORDER BY CAST(
        SUBSTR(teacher_id, 5) AS INTEGER
      ) DESC
      LIMIT 1
      `
    )
    .first();


  let number = 1;

  if (row?.teacher_id) {

    const n =
      parseInt(
        row.teacher_id.substring(4),
        10
      );

    if (Number.isFinite(n)) {
      number = n + 1;
    }
  }


  return `RKM-${String(number).padStart(3, "0")}`;
}


async function getTeachers(
  request,
  env
) {

  const rows =
    await env.DB.prepare(
      `
      SELECT
        t.*,
        s.name AS subject_name,
        s.name_bn AS subject_name_bn
      FROM teachers t
      LEFT JOIN subjects s
        ON s.id = t.subject_id
      WHERE t.status = 'active'
      ORDER BY t.teacher_id
      `
    )
    .all();

  return ok(
    {
      teachers:
        rows.results || []
    },
    request
  );
}


async function createTeacher(
  request,
  env,
  auth
) {

  const data =
    await body(request);

  if (!data.name) {

    return error(
      "Teacher name is required",
      400,
      request
    );
  }


  const teacherId =
    await generateTeacherId(env);

  const idValue =
    id("teacher");


  await env.DB.prepare(
    `
    INSERT INTO teachers
    (
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
    idValue,
    teacherId,
    data.name,
    data.name_bn || null,
    data.subject_id || null,
    data.designation || null,
    data.phone || null,
    data.email || null,
    data.qualification || null,
    data.address || null,
    data.photo_url || null,
    data.joining_date || null,
    data.employment_type || null,
    data.status || "active"
  )
  .run();


  await logAdmin(
    env,
    auth.user.id,
    "CREATE_TEACHER",
    "teacher",
    idValue,
    `${teacherId} - ${data.name}`
  );


  return ok(
    {
      id: idValue,
      teacher_id: teacherId,
      message: "Teacher created"
    },
    request
  );
}


/* =======================================================
   EXAM TYPES
======================================================= */

async function getExamTypes(
  request,
  env
) {

  const rows =
    await env.DB.prepare(
      `
      SELECT *
      FROM exam_types
      WHERE status = 'active'
      ORDER BY category, name
      `
    )
    .all();

  return ok(
    {
      exam_types:
        rows.results || []
    },
    request
  );
}


/* =======================================================
   EXAMS
======================================================= */

async function getExams(
  request,
  env
) {

  const url =
    new URL(request.url);

  const year =
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

      ay.year AS academic_year,

      c.class_number,
      c.name AS class_name,

      g.name AS group_name,

      et.name AS exam_type_name,
      et.category AS exam_category

    FROM exams e

    JOIN academic_years ay
      ON ay.id = e.academic_year_id

    JOIN classes c
      ON c.id = e.class_id

    LEFT JOIN groups g
      ON g.id = e.group_id

    JOIN exam_types et
      ON et.id = e.exam_type_id

    WHERE 1=1
  `;


  const params = [];


  if (year) {
    sql += ` AND e.academic_year_id = ?`;
    params.push(year);
  }

  if (classId) {
    sql += ` AND e.class_id = ?`;
    params.push(classId);
  }

  if (groupId) {
    sql += ` AND e.group_id = ?`;
    params.push(groupId);
  }


  sql += `
    ORDER BY ay.year DESC, e.created_at DESC
  `;


  const rows =
    await env.DB.prepare(sql)
      .bind(...params)
      .all();


  return ok(
    {
      exams:
        rows.results || []
    },
    request
  );
}


async function createExam(
  request,
  env,
  auth
) {

  const data =
    await body(request);


  if (
    !data.exam_type_id ||
    !data.academic_year_id ||
    !data.class_id ||
    !data.name
  ) {

    return error(
      "exam_type_id, academic_year_id, class_id and name are required",
      400,
      request
    );
  }


  const examId =
    id("exam");


  await env.DB.prepare(
    `
    INSERT INTO exams
    (
      id,
      exam_type_id,
      academic_year_id,
      class_id,
      group_id,
      name,
      name_bn,
      start_date,
      end_date,
      published,
      created_by
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
  )
  .bind(
    examId,
    data.exam_type_id,
    data.academic_year_id,
    data.class_id,
    data.group_id || null,
    data.name,
    data.name_bn || null,
    data.start_date || null,
    data.end_date || null,
    bool(data.published) ? 1 : 0,
    auth.user.id
  )
  .run();


  await logAdmin(
    env,
    auth.user.id,
    "CREATE_EXAM",
    "exam",
    examId,
    data.name
  );


  return ok(
    {
      id: examId,
      message: "Exam created"
    },
    request
  );
}


/* =======================================================
   EXAM SUBJECTS
======================================================= */

async function getExamSubjects(
  request,
  env
) {

  const url =
    new URL(request.url);

  const examId =
    url.searchParams.get(
      "exam_id"
    );


  if (!examId) {

    return error(
      "exam_id is required",
      400,
      request
    );
  }


  const rows =
    await env.DB.prepare(
      `
      SELECT
        es.*,
        s.name AS subject_name,
        s.name_bn AS subject_name_bn

      FROM exam_subjects es

      JOIN subjects s
        ON s.id = es.subject_id

      WHERE es.exam_id = ?

      ORDER BY es.display_order ASC
      `
    )
    .bind(examId)
    .all();


  return ok(
    {
      exam_subjects:
        rows.results || []
    },
    request
  );
}


async function createExamSubject(
  request,
  env,
  auth
) {

  const data =
    await body(request);


  if (
    !data.exam_id ||
    !data.subject_id
  ) {

    return error(
      "exam_id and subject_id are required",
      400,
      request
    );
  }


  const subjectId =
    id("exam_subject");


  await env.DB.prepare(
    `
    INSERT INTO exam_subjects
    (
      id,
      exam_id,
      subject_id,
      full_marks,
      pass_marks,
      exam_date,
      exam_time,
      display_order
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `
  )
  .bind(
    subjectId,
    data.exam_id,
    data.subject_id,
    cleanNumber(data.full_marks, 100),
    cleanNumber(data.pass_marks, 33),
    data.exam_date || null,
    data.exam_time || null,
    cleanNumber(data.display_order)
  )
  .run();


  await logAdmin(
    env,
    auth.user.id,
    "ADD_EXAM_SUBJECT",
    "exam_subject",
    subjectId,
    data.subject_id
  );


  return ok(
    {
      id: subjectId,
      message: "Exam subject added"
    },
    request
  );
}


/* =======================================================
   MARKSHEETS
======================================================= */


/*
GET /api/marksheets

Filters:

exam_id
academic_year_id
class_id
group_id
roll
name
published
*/

async function getMarksheets(
  request,
  env
) {

  const url =
    new URL(request.url);


  const examId =
    url.searchParams.get("exam_id");

  const yearId =
    url.searchParams.get(
      "academic_year_id"
    );

  const classId =
    url.searchParams.get("class_id");

  const groupId =
    url.searchParams.get(
      "group_id"
    );

  const roll =
    url.searchParams.get("roll");

  const name =
    url.searchParams.get("name");


  let sql = `
    SELECT

      m.*,

      ay.year AS academic_year,

      c.class_number,
      c.name AS class_name,

      g.name AS group_name

    FROM marksheets m

    JOIN academic_years ay
      ON ay.id = m.academic_year_id

    JOIN classes c
      ON c.id = m.class_id

    LEFT JOIN groups g
      ON g.id = m.group_id

    WHERE 1=1
  `;


  const params = [];


  if (examId) {
    sql += `
      AND m.exam_id = ?
    `;
    params.push(examId);
  }


  if (yearId) {
    sql += `
      AND m.academic_year_id = ?
    `;
    params.push(yearId);
  }


  if (classId) {
    sql += `
      AND m.class_id = ?
    `;
    params.push(classId);
  }


  if (groupId) {
    sql += `
      AND m.group_id = ?
    `;
    params.push(groupId);
  }


  if (roll) {
    sql += `
      AND m.roll_number = ?
    `;
    params.push(Number(roll));
  }


  if (name) {
    sql += `
      AND LOWER(m.student_name)
      LIKE LOWER(?)
    `;
    params.push(`%${name}%`);
  }


  sql += `
    ORDER BY
      m.roll_number ASC,
      m.student_name ASC
  `;


  const rows =
    await env.DB.prepare(sql)
      .bind(...params)
      .all();


  return ok(
    {
      marksheets:
        rows.results || []
    },
    request
  );
}


/*
GET SINGLE MARKSHEET
/api/marksheets/:id
*/

async function getSingleMarksheet(
  request,
  env,
  marksheetId
) {

  const marksheet =
    await env.DB.prepare(
      `
      SELECT

        m.*,

        ay.year AS academic_year,

        c.class_number,
        c.name AS class_name,

        g.name AS group_name,

        e.name AS exam_name

      FROM marksheets m

      JOIN academic_years ay
        ON ay.id = m.academic_year_id

      JOIN classes c
        ON c.id = m.class_id

      LEFT JOIN groups g
        ON g.id = m.group_id

      JOIN exams e
        ON e.id = m.exam_id

      WHERE m.id = ?

      LIMIT 1
      `
    )
    .bind(marksheetId)
    .first();


  if (!marksheet) {

    return error(
      "Marksheet not found",
      404,
      request
    );
  }


  const subjects =
    await env.DB.prepare(
      `
      SELECT

        ms.*,

        s.name AS subject_name,
        s.name_bn AS subject_name_bn

      FROM marksheet_subjects ms

      JOIN subjects s
        ON s.id = ms.subject_id

      WHERE ms.marksheet_id = ?

      ORDER BY ms.display_order ASC
      `
    )
    .bind(marksheetId)
    .all();


  return ok(
    {
      marksheet,
      subjects:
        subjects.results || []
    },
    request
  );
}


/*
CREATE SINGLE STUDENT MARKSHEET
*/

async function createMarksheet(
  request,
  env,
  auth
) {

  const data =
    await body(request);


  if (
    !data.exam_id ||
    !data.academic_year_id ||
    !data.class_id ||
    !data.student_name ||
    data.roll_number === undefined
  ) {

    return error(
      "exam_id, academic_year_id, class_id, student_name and roll_number are required",
      400,
      request
    );
  }


  const marksheetId =
    id("marksheet");


  const roll =
    Number(data.roll_number);


  if (
    !Number.isInteger(roll) ||
    roll < 1
  ) {

    return error(
      "Invalid roll number",
      400,
      request
    );
  }


  await env.DB.prepare(
    `
    INSERT INTO marksheets
    (
      id,
      exam_id,
      academic_year_id,
      class_id,
      group_id,
      student_name,
      student_name_bn,
      roll_number,
      registration_number,
      published
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
  )
  .bind(
    marksheetId,
    data.exam_id,
    data.academic_year_id,
    data.class_id,
    data.group_id || null,
    data.student_name,
    data.student_name_bn || null,
    roll,
    data.registration_number || null,
    bool(data.published) ? 1 : 0
  )
  .run();


  /*
  Add subjects if supplied.

  Example:

  subjects: [
    {
      subject_id: "...",
      marks: 85,
      full_marks: 100,
      pass_marks: 33
    }
  ]
  */

  if (Array.isArray(data.subjects)) {

    let order = 0;

    for (const subject of data.subjects) {

      const marks =
        cleanNumber(subject.marks);

      const full =
        cleanNumber(
          subject.full_marks,
          100
        );

      const pass =
        cleanNumber(
          subject.pass_marks,
          33
        );


      const [grade, gp] =
        gradeFor(
          full > 0
            ? (marks / full) * 100
            : 0
        );


      await env.DB.prepare(
        `
        INSERT INTO marksheet_subjects
        (
          id,
          marksheet_id,
          subject_id,
          full_marks,
          pass_marks,
          marks,
          grade,
          grade_point,
          result_status,
          display_order
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `
      )
      .bind(
        id("ms_subject"),
        marksheetId,
        subject.subject_id,
        full,
        pass,
        marks,
        grade,
        gp,
        resultFor(marks, pass),
        order++
      )
      .run();
    }
  }


  await calculateMarksheet(
    env,
    marksheetId
  );


  await logAdmin(
    env,
    auth.user.id,
    "CREATE_MARKSHEET",
    "marksheet",
    marksheetId,
    data.student_name
  );


  return ok(
    {
      id: marksheetId,
      message:
        "Student marksheet created"
    },
    request
  );
}


/*
ADD SUBJECT TO SINGLE MARKSHEET

Only:
Subject Name
Obtained Marks
*/

async function addMarksheetSubject(
  request,
  env,
  auth,
  marksheetId
) {

  const data =
    await body(request);


  if (!data.subject_id) {

    return error(
      "subject_id is required",
      400,
      request
    );
  }


  const marks =
    cleanNumber(data.marks);

  const full =
    cleanNumber(
      data.full_marks,
      100
    );

  const pass =
    cleanNumber(
      data.pass_marks,
      33
    );


  const [grade, gp] =
    gradeFor(
      full > 0
        ? (marks / full) * 100
        : 0
    );


  const maxOrder =
    await env.DB.prepare(
      `
      SELECT
        COALESCE(MAX(display_order), -1)
        AS max_order
      FROM marksheet_subjects
      WHERE marksheet_id = ?
      `
    )
    .bind(marksheetId)
    .first();


  const displayOrder =
    Number(maxOrder?.max_order ?? -1) + 1;


  const subjectRow =
    await env.DB.prepare(
      `
      SELECT id
      FROM subjects
      WHERE id = ?
      `
    )
    .bind(data.subject_id)
    .first();


  if (!subjectRow) {

    return error(
      "Subject not found",
      404,
      request
    );
  }


  await env.DB.prepare(
    `
    INSERT INTO marksheet_subjects
    (
      id,
      marksheet_id,
      subject_id,
      full_marks,
      pass_marks,
      marks,
      grade,
      grade_point,
      result_status,
      display_order
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
  )
  .bind(
    id("ms_subject"),
    marksheetId,
    data.subject_id,
    full,
    pass,
    marks,
    grade,
    gp,
    resultFor(marks, pass),
    displayOrder
  )
  .run();


  await calculateMarksheet(
    env,
    marksheetId
  );


  await logAdmin(
    env,
    auth.user.id,
    "ADD_MARKSHEET_SUBJECT",
    "marksheet",
    marksheetId,
    data.subject_id
  );


  return ok(
    {
      message:
        "Subject added"
    },
    request
  );
}


/*
UPDATE SUBJECT MARKS
*/

async function updateMarksheetSubject(
  request,
  env,
  auth,
  subjectRowId
) {

  const data =
    await body(request);


  const existing =
    await env.DB.prepare(
      `
      SELECT *
      FROM marksheet_subjects
      WHERE id = ?
      LIMIT 1
      `
    )
    .bind(subjectRowId)
    .first();


  if (!existing) {

    return error(
      "Marksheet subject not found",
      404,
      request
    );
  }


  const marks =
    cleanNumber(
      data.marks,
      existing.marks
    );

  const full =
    cleanNumber(
      data.full_marks,
      existing.full_marks
    );

  const pass =
    cleanNumber(
      data.pass_marks,
      existing.pass_marks
    );


  const [grade, gp] =
    gradeFor(
      full > 0
        ? (marks / full) * 100
        : 0
    );


  await env.DB.prepare(
    `
    UPDATE marksheet_subjects
    SET
      full_marks = ?,
      pass_marks = ?,
      marks = ?,
      grade = ?,
      grade_point = ?,
      result_status = ?,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    `
  )
  .bind(
    full,
    pass,
    marks,
    grade,
    gp,
    resultFor(marks, pass),
    subjectRowId
  )
  .run();


  await calculateMarksheet(
    env,
    existing.marksheet_id
  );


  return ok(
    {
      message:
        "Marks updated"
    },
    request
  );
}


/*
DELETE SUBJECT
*/

async function deleteMarksheetSubject(
  request,
  env,
  auth,
  subjectRowId
) {

  const row =
    await env.DB.prepare(
      `
      SELECT marksheet_id
      FROM marksheet_subjects
      WHERE id = ?
      `
    )
    .bind(subjectRowId)
    .first();


  if (!row) {

    return error(
      "Subject not found",
      404,
      request
    );
  }


  await env.DB.prepare(
    `
    DELETE FROM marksheet_subjects
    WHERE id = ?
    `
  )
  .bind(subjectRowId)
  .run();


  await calculateMarksheet(
    env,
    row.marksheet_id
  );


  await logAdmin(
    env,
    auth.user.id,
    "DELETE_MARKSHEET_SUBJECT",
    "marksheet_subject",
    subjectRowId,
    null
  );


  return ok(
    {
      message:
        "Subject removed"
    },
    request
  );
}


/* =======================================================
   MANUAL RANK
======================================================= */

async function updateRank(
  request,
  env,
  auth,
  marksheetId
) {

  const data =
    await body(request);


  if (
    data.rank !== null &&
    data.rank !== undefined &&
    (
      !Number.isInteger(
        Number(data.rank)
      ) ||
      Number(data.rank) < 1
    )
  ) {

    return error(
      "Rank must be a positive integer or null",
      400,
      request
    );
  }


  const rank =
    data.rank === null ||
    data.rank === undefined
      ? null
      : Number(data.rank);


  await env.DB.prepare(
    `
    UPDATE marksheets
    SET
      rank = ?,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    `
  )
  .bind(
    rank,
    marksheetId
  )
  .run();


  await logAdmin(
    env,
    auth.user.id,
    "UPDATE_MANUAL_RANK",
    "marksheet",
    marksheetId,
    `Manual rank: ${rank}`
  );


  return ok(
    {
      rank,
      message:
        "Manual rank updated"
    },
    request
  );
}


/* =======================================================
   CLASS FULL MARKSHEET
======================================================= */

/*
One API call returns every student's
complete marksheet.

GET:
 /api/class-marksheet
   ?exam_id=...
   &class_id=...
   &group_id=...
*/

async function getClassMarksheet(
  request,
  env
) {

  const url =
    new URL(request.url);


  const examId =
    url.searchParams.get(
      "exam_id"
    );

  const classId =
    url.searchParams.get(
      "class_id"
    );

  const groupId =
    url.searchParams.get(
      "group_id"
    );


  if (!examId || !classId) {

    return error(
      "exam_id and class_id are required",
      400,
      request
    );
  }


  let sql = `
    SELECT
      m.*,
      c.class_number,
      c.name AS class_name,
      g.name AS group_name
    FROM marksheets m

    JOIN classes c
      ON c.id = m.class_id

    LEFT JOIN groups g
      ON g.id = m.group_id

    WHERE
      m.exam_id = ?
      AND m.class_id = ?
  `;


  const params = [
    examId,
    classId
  ];


  if (groupId) {

    sql += `
      AND m.group_id = ?
    `;

    params.push(groupId);
  }


  sql += `
    ORDER BY
      m.roll_number ASC
  `;


  const marksheets =
    await env.DB
      .prepare(sql)
      .bind(...params)
      .all();


  const students =
    marksheets.results || [];


  const result = [];


  for (const student of students) {

    const subjects =
      await env.DB.prepare(
        `
        SELECT
          ms.*,
          s.name AS subject_name,
          s.name_bn AS subject_name_bn

        FROM marksheet_subjects ms

        JOIN subjects s
          ON s.id = ms.subject_id

        WHERE ms.marksheet_id = ?

        ORDER BY ms.display_order
        `
      )
      .bind(student.id)
      .all();


    result.push({
      ...student,
      subjects:
        subjects.results || []
    });
  }


  return ok(
    {
      count: result.length,
      students: result
    },
    request
  );
}


/* =======================================================
   BOARD RESULTS
======================================================= */

async function getBoardResults(
  request,
  env
) {

  const url =
    new URL(request.url);


  const type =
    url.searchParams.get(
      "type"
    );

  const year =
    url.searchParams.get(
      "year"
    );

  const roll =
    url.searchParams.get(
      "roll"
    );


  let sql = `
    SELECT *
    FROM board_results
    WHERE published = 1
  `;


  const params = [];


  if (type) {

    sql += `
      AND result_type = ?
    `;

    params.push(type);
  }


  if (year) {

    sql += `
      AND result_year = ?
    `;

    params.push(Number(year));
  }


  if (roll) {

    sql += `
      AND roll_number = ?
    `;

    params.push(roll);
  }


  sql += `
    ORDER BY result_year DESC, roll_number ASC
  `;


  const rows =
    await env.DB.prepare(sql)
      .bind(...params)
      .all();


  return ok(
    {
      results:
        rows.results || []
    },
    request
  );
}


async function createBoardResult(
  request,
  env,
  auth
) {

  const data =
    await body(request);


  const allowed = [
    "dakhil",
    "alim",
    "fazil",
    "kamil"
  ];


  if (
    !allowed.includes(
      data.result_type
    )
  ) {

    return error(
      "Invalid result type",
      400,
      request
    );
  }


  if (!data.student_name) {

    return error(
      "student_name is required",
      400,
      request
    );
  }


  const resultId =
    id("board_result");


  await env.DB.prepare(
    `
    INSERT INTO board_results
    (
      id,
      result_type,
      academic_year_id,
      student_name,
      roll_number,
      registration_number,
      result_year,
      total_marks,
      percentage,
      grade,
      grade_point,
      result_status,
      result_data,
      published,
      created_by
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
  )
  .bind(
    resultId,
    data.result_type,
    data.academic_year_id || null,
    data.student_name,
    data.roll_number || null,
    data.registration_number || null,
    data.result_year || null,
    data.total_marks || null,
    data.percentage || null,
    data.grade || null,
    data.grade_point || null,
    data.result_status || null,
    JSON.stringify(
      data.result_data || {}
    ),
    bool(data.published) ? 1 : 0,
    auth.user.id
  )
  .run();


  if (
    Array.isArray(
      data.subjects
    )
  ) {

    let order = 0;

    for (
      const subject
      of data.subjects
    ) {

      await env.DB.prepare(
        `
        INSERT INTO board_result_subjects
        (
          id,
          board_result_id,
          subject_name,
          full_marks,
          obtained_marks,
          grade,
          grade_point,
          display_order
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `
      )
      .bind(
        id("board_subject"),
        resultId,
        subject.subject_name,
        subject.full_marks ?? null,
        subject.obtained_marks ?? null,
        subject.grade || null,
        subject.grade_point ?? null,
        order++
      )
      .run();
    }
  }


  await logAdmin(
    env,
    auth.user.id,
    "CREATE_BOARD_RESULT",
    "board_result",
    resultId,
    data.result_type
  );


  return ok(
    {
      id: resultId,
      message:
        "Board result created"
    },
    request
  );
}


/* =======================================================
   NOTICES
======================================================= */

async function getNotices(
  request,
  env
) {

  const rows =
    await env.DB.prepare(
      `
      SELECT *
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

      ORDER BY created_at DESC
      `
    )
    .all();


  return ok(
    {
      notices:
        rows.results || []
    },
    request
  );
}


async function createNotice(
  request,
  env,
  auth
) {

  const data =
    await body(request);


  if (
    !data.title ||
    !data.content
  ) {

    return error(
      "title and content are required",
      400,
      request
    );
  }


  const noticeId =
    id("notice");


  await env.DB.prepare(
    `
    INSERT INTO notices
    (
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
    data.title,
    data.title_bn || null,
    data.content,
    data.content_bn || null,
    data.category || "general",
    data.attachment_url || null,
    bool(data.published) ? 1 : 0,
    data.publish_at || null,
    data.expires_at || null,
    auth.user.id
  )
  .run();


  await logAdmin(
    env,
    auth.user.id,
    "CREATE_NOTICE",
    "notice",
    noticeId,
    data.title
  );


  return ok(
    {
      id: noticeId,
      message:
        "Notice created"
    },
    request
  );
}


/* =======================================================
   HERO ADS
======================================================= */

async function getHeroAds(
  request,
  env
) {

  const rows =
    await env.DB.prepare(
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
        rows.results || []
    },
    request
  );
}


async function createHeroAd(
  request,
  env,
  auth
) {

  const data =
    await body(request);


  if (!data.title) {

    return error(
      "title is required",
      400,
      request
    );
  }


  const adId =
    id("hero");


  await env.DB.prepare(
    `
    INSERT INTO hero_ads
    (
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
    adId,
    data.title,
    data.description || null,
    data.image_url || null,
    data.button_text || null,
    data.button_url || null,
    cleanNumber(data.display_order),
    data.status || "inactive",
    data.start_at || null,
    data.end_at || null,
    auth.user.id
  )
  .run();


  await logAdmin(
    env,
    auth.user.id,
    "CREATE_HERO_AD",
    "hero_ad",
    adId,
    data.title
  );


  return ok(
    {
      id: adId,
      message:
        "Hero ad created"
    },
    request
  );
}


/* =======================================================
   EVENTS
======================================================= */

async function getEvents(
  request,
  env
) {

  const rows =
    await env.DB.prepare(
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
        rows.results || []
    },
    request
  );
}


async function createEvent(
  request,
  env,
  auth
) {

  const data =
    await body(request);


  if (
    !data.title ||
    !data.start_datetime
  ) {

    return error(
      "title and start_datetime are required",
      400,
      request
    );
  }


  const eventId =
    id("event");


  await env.DB.prepare(
    `
    INSERT INTO events
    (
      id,
      title,
      title_bn,
      description,
      description_bn,
      image_url,
      location,
      start_datetime,
      end_datetime,
      status,
      created_by
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
  )
  .bind(
    eventId,
    data.title,
    data.title_bn || null,
    data.description || null,
    data.description_bn || null,
    data.image_url || null,
    data.location || null,
    data.start_datetime,
    data.end_datetime || null,
    data.status || "active",
    auth.user.id
  )
  .run();


  await logAdmin(
    env,
    auth.user.id,
    "CREATE_EVENT",
    "event",
    eventId,
    data.title
  );


  return ok(
    {
      id: eventId,
      message:
        "Event created"
    },
    request
  );
}


/* =======================================================
   GALLERY
======================================================= */

async function getGallery(
  request,
  env
) {

  const url =
    new URL(request.url);

  const category =
    url.searchParams.get(
      "category"
    );


  let sql = `
    SELECT *
    FROM gallery
    WHERE published = 1
  `;

  const params = [];


  if (category) {

    sql += `
      AND category = ?
    `;

    params.push(category);
  }


  sql += `
    ORDER BY display_order ASC,
             created_at DESC
  `;


  const rows =
    await env.DB.prepare(sql)
      .bind(...params)
      .all();


  return ok(
    {
      gallery:
        rows.results || []
    },
    request
  );
}


async function createGallery(
  request,
  env,
  auth
) {

  const data =
    await body(request);


  if (!data.image_url) {

    return error(
      "image_url is required",
      400,
      request
    );
  }


  const galleryId =
    id("gallery");


  await env.DB.prepare(
    `
    INSERT INTO gallery
    (
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
    data.title || null,
    data.description || null,
    data.image_url,
    data.category || "general",
    cleanNumber(data.display_order),
    data.published === undefined
      ? 1
      : bool(data.published)
        ? 1
        : 0,
    auth.user.id
  )
  .run();


  return ok(
    {
      id: galleryId,
      message:
        "Gallery item created"
    },
    request
  );
}


/* =======================================================
   DOCUMENTS
======================================================= */

async function getDocuments(
  request,
  env
) {

  const rows =
    await env.DB.prepare(
      `
      SELECT
        id,
        title,
        description,
        file_name,
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
        rows.results || []
    },
    request
  );
}


/* =======================================================
   CURRENT USER
======================================================= */

async function getMe(
  request,
  env
) {

  const auth =
    await authenticate(
      request,
      env
    );


  return ok(
    {
      user:
        auth.user
    },
    request
  );
}


/* =======================================================
   AUTH SYNC
======================================================= */

async function authSync(
  request,
  env
) {

  const token =
    getBearer(request);


  if (!token) {

    return error(
      "Firebase token required",
      401,
      request
    );
  }


  const firebase =
    await verifyFirebaseToken(
      token
    );


  const uid =
    firebase.sub;


  const existing =
    await env.DB.prepare(
      `
      SELECT *
      FROM users
      WHERE firebase_uid = ?
      LIMIT 1
      `
    )
    .bind(uid)
    .first();


  const name =
    firebase.name ||
    firebase.email ||
    "User";


  const email =
    firebase.email ||
    null;


  const photo =
    firebase.picture ||
    null;


  if (existing) {

    await env.DB.prepare(
      `
      UPDATE users
      SET
        name = ?,
        email = ?,
        photo_url = ?,
        last_login_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE firebase_uid = ?
      `
    )
    .bind(
      name,
      email,
      photo,
      uid
    )
    .run();


    const user =
      await env.DB.prepare(
        `
        SELECT *
        FROM users
        WHERE firebase_uid = ?
        `
      )
      .bind(uid)
      .first();


    return ok(
      {
        user
      },
      request
    );
  }


  /*
  New users are ALWAYS user.

  Admin role must be manually assigned
  in D1/Admin Panel.
  */

  const userId =
    id("user");


  await env.DB.prepare(
    `
    INSERT INTO users
    (
      id,
      firebase_uid,
      name,
      email,
      photo_url,
      role,
      status,
      last_login_at
    )
    VALUES (?, ?, ?, ?, ?, 'user', 'active', CURRENT_TIMESTAMP)
    `
  )
  .bind(
    userId,
    uid,
    name,
    email,
    photo
  )
  .run();


  const user =
    await env.DB.prepare(
      `
      SELECT *
      FROM users
      WHERE id = ?
      `
    )
    .bind(userId)
    .first();


  return ok(
    {
      user
    },
    request
  );
}


/* =======================================================
   ADMIN USERS
======================================================= */

async function getAdminUsers(
  request,
  env
) {

  const rows =
    await env.DB.prepare(
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
        rows.results || []
    },
    request
  );
}


async function updateUserRole(
  request,
  env,
  auth,
  userId
) {

  const data =
    await body(request);


  if (
    !["admin", "user"]
      .includes(data.role)
  ) {

    return error(
      "Invalid role",
      400,
      request
    );
  }


  await env.DB.prepare(
    `
    UPDATE users
    SET
      role = ?,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    `
  )
  .bind(
    data.role,
    userId
  )
  .run();


  await logAdmin(
    env,
    auth.user.id,
    "UPDATE_USER_ROLE",
    "user",
    userId,
    data.role
  );


  return ok(
    {
      message:
        "User role updated"
    },
    request
  );
}


async function updateUserStatus(
  request,
  env,
  auth,
  userId
) {

  const data =
    await body(request);


  const allowed = [
    "active",
    "inactive",
    "suspended"
  ];


  if (
    !allowed.includes(
      data.status
    )
  ) {

    return error(
      "Invalid status",
      400,
      request
    );
  }


  await env.DB.prepare(
    `
    UPDATE users
    SET
      status = ?,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    `
  )
  .bind(
    data.status,
    userId
  )
  .run();


  await logAdmin(
    env,
    auth.user.id,
    "UPDATE_USER_STATUS",
    "user",
    userId,
    data.status
  );


  return ok(
    {
      message:
        "User status updated"
    },
    request
  );
}


/* =======================================================
   NOTIFICATIONS
======================================================= */

async function getNotifications(
  request,
  env
) {

  const auth =
    await authenticate(
      request,
      env
    );


  const rows =
    await env.DB.prepare(
      `
      SELECT *
      FROM notifications
      WHERE user_id = ?
      ORDER BY created_at DESC
      `
    )
    .bind(auth.user.id)
    .all();


  return ok(
    {
      notifications:
        rows.results || []
    },
    request
  );
}


async function markNotificationRead(
  request,
  env,
  notificationId
) {

  const auth =
    await authenticate(
      request,
      env
    );


  await env.DB.prepare(
    `
    UPDATE notifications
    SET is_read = 1
    WHERE id = ?
      AND user_id = ?
    `
  )
  .bind(
    notificationId,
    auth.user.id
  )
  .run();


  return ok(
    {
      message:
        "Notification marked as read"
    },
    request
  );
}


/* =======================================================
   ACADEMIC PROMOTION
======================================================= */

/*
IMPORTANT LOGIC

2026:

Class 1 -> Class 2
Class 2 -> Class 3
...
Class 9 -> Class 10

Next roll =
previous Annual Exam manual rank.

Class 10:
-> X-10 archive

No automatic ranking.
Only manually assigned rank becomes next roll.
*/


async function promoteAcademicYear(
  request,
  env,
  auth,
  yearId
) {

  const currentYear =
    await env.DB.prepare(
      `
      SELECT *
      FROM academic_years
      WHERE id = ?
      `
    )
    .bind(yearId)
    .first();


  if (!currentYear) {

    return error(
      "Academic year not found",
      404,
      request
    );
  }


  const nextYearNumber =
    Number(currentYear.year) + 1;


  let nextYear =
    await env.DB.prepare(
      `
      SELECT *
      FROM academic_years
      WHERE year = ?
      `
    )
    .bind(nextYearNumber)
    .first();


  if (!nextYear) {

    const nextId =
      id("year");


    await env.DB.prepare(
      `
      INSERT INTO academic_years
      (
        id,
        year,
        status,
        is_current
      )
      VALUES (?, ?, 'active', 1)
      `
    )
    .bind(
      nextId,
      nextYearNumber
    )
    .run();


    nextYear =
      await env.DB.prepare(
        `
        SELECT *
        FROM academic_years
        WHERE id = ?
        `
      )
      .bind(nextId)
      .first();
  }


  /*
  Find Annual exam.
  */

  const annual =
    await env.DB.prepare(
      `
      SELECT e.*
      FROM exams e

      JOIN exam_types et
        ON et.id = e.exam_type_id

      WHERE e.academic_year_id = ?

      AND (
        LOWER(et.name) = 'annual'
        OR LOWER(et.name_bn) = 'বার্ষিক'
      )

      ORDER BY e.created_at DESC
      LIMIT 1
      `
    )
    .bind(yearId)
    .first();


  if (!annual) {

    return error(
      "Annual exam not found for this academic year",
      400,
      request
    );
  }


  const rows =
    await env.DB.prepare(
      `
      SELECT *
      FROM marksheets
      WHERE exam_id = ?
      ORDER BY roll_number ASC
      `
    )
    .bind(annual.id)
    .all();


  const students =
    rows.results || [];


  let promoted = 0;
  let archived = 0;


  for (const student of students) {

    const classRow =
      await env.DB.prepare(
        `
        SELECT *
        FROM classes
        WHERE id = ?
        `
      )
      .bind(student.class_id)
      .first();


    if (!classRow) {
      continue;
    }


    const oldClass =
      Number(classRow.class_number);


    /*
    Class 10 -> X-10
    */

    if (oldClass === 10) {

      await env.DB.prepare(
        `
        UPDATE marksheets
        SET
          progression_status = 'x10_archive',
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        `
      )
      .bind(student.id)
      .run();


      archived++;

      continue;
    }


    const newClassNumber =
      oldClass + 1;


    const newClass =
      await env.DB.prepare(
        `
        SELECT *
        FROM classes
        WHERE class_number = ?
        LIMIT 1
        `
      )
      .bind(newClassNumber)
      .first();


    if (!newClass) {
      continue;
    }


    /*
    Manual Annual Rank
    becomes next year's Roll.

    If rank is empty:
    keep old roll as fallback.
    */

    const nextRoll =
      student.rank
        ? Number(student.rank)
        : Number(student.roll_number);


    /*
    Create placeholder mark sheet
    for next year.

    This does NOT copy old marks.
    */

    const newMarksheetId =
      id("marksheet");


    /*
    Find/create next year's
    transition exam.
    */

    let nextExam =
      await env.DB.prepare(
        `
        SELECT e.*
        FROM exams e
        JOIN exam_types et
          ON et.id = e.exam_type_id

        WHERE e.academic_year_id = ?
          AND e.class_id = ?
          AND (
            LOWER(et.name) = 'annual'
            OR LOWER(et.name_bn) = 'বার্ষিক'
          )

        LIMIT 1
        `
      )
      .bind(
        nextYear.id,
        newClass.id
      )
      .first();


    if (!nextExam) {

      nextExam =
        await env.DB.prepare(
          `
          SELECT e.*
          FROM exams e
          WHERE e.academic_year_id = ?
            AND e.class_id = ?
          ORDER BY e.created_at ASC
          LIMIT 1
          `
        )
        .bind(
          nextYear.id,
          newClass.id
        )
        .first();
    }


    /*
    If no exam exists,
    don't create invalid marksheet.
    */

    if (!nextExam) {
      continue;
    }


    await env.DB.prepare(
      `
      INSERT INTO marksheets
      (
        id,
        exam_id,
        academic_year_id,
        class_id,
        group_id,
        student_name,
        student_name_bn,
        roll_number,
        registration_number,
        progression_status,
        previous_marksheet_id,
        published
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'promoted', ?, 0)
      `
    )
    .bind(
      newMarksheetId,
      nextExam.id,
      nextYear.id,
      newClass.id,
      student.group_id,
      student.student_name,
      student.student_name_bn,
      nextRoll,
      student.registration_number,
      student.id
    )
    .run();


    promoted++;
  }


  /*
  Current year completed.
  */

  await env.DB.prepare(
    `
    UPDATE academic_years
    SET
      status = 'completed',
      is_current = 0,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    `
  )
  .bind(yearId)
  .run();


  await env.DB.prepare(
    `
    UPDATE academic_years
    SET
      status = 'active',
      is_current = 1,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    `
  )
  .bind(nextYear.id)
  .run();


  await logAdmin(
    env,
    auth.user.id,
    "ACADEMIC_YEAR_PROMOTION",
    "academic_year",
    yearId,
    `Promoted ${promoted}; X-10 archived ${archived}`
  );


  return ok(
    {
      message:
        "Academic year promotion completed",

      from_year:
        currentYear.year,

      to_year:
        nextYear.year,

      promoted,
      x10_archived: archived,

      rule:
        "Manual Annual Rank becomes next year's roll"
    },
    request
  );
}


/* =======================================================
   ROUTER
======================================================= */

export default {

  async fetch(request, env) {

    if (request.method === "OPTIONS") {
      return options(request);
    }


    const url =
      new URL(request.url);

    const path =
      url.pathname.replace(
        /\/+$/,
        ""
      ) || "/";


    try {

      /* =================================================
         PUBLIC
      ================================================= */

      if (
        request.method === "GET" &&
        path === "/"
      ) {
        return root(request);
      }


      if (
        request.method === "GET" &&
        path === "/api/health"
      ) {
        return health(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/settings"
      ) {
        return getSettings(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/academic-years"
      ) {
        return getAcademicYears(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/classes"
      ) {
        return getClasses(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/groups"
      ) {
        return getGroups(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/subjects"
      ) {
        return getSubjects(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/teachers"
      ) {
        return getTeachers(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/exam-types"
      ) {
        return getExamTypes(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/exams"
      ) {
        return getExams(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/exam-subjects"
      ) {
        return getExamSubjects(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/marksheets"
      ) {
        return getMarksheets(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/class-marksheet"
      ) {
        return getClassMarksheet(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/results"
      ) {
        return getBoardResults(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/notices"
      ) {
        return getNotices(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/hero-ads"
      ) {
        return getHeroAds(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/events"
      ) {
        return getEvents(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/gallery"
      ) {
        return getGallery(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/documents"
      ) {
        return getDocuments(
          request,
          env
        );
      }


      /* =================================================
         AUTH
      ================================================= */

      if (
        request.method === "POST" &&
        path === "/api/auth/sync"
      ) {
        return authSync(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/me"
      ) {
        return getMe(
          request,
          env
        );
      }


      if (
        request.method === "GET" &&
        path === "/api/notifications"
      ) {
        return getNotifications(
          request,
          env
        );
      }


      const notificationMatch =
        path.match(
          /^\/api\/notifications\/([^/]+)\/read$/
        );


      if (
        request.method === "PATCH" &&
        notificationMatch
      ) {

        return markNotificationRead(
          request,
          env,
          notificationMatch[1]
        );
      }


      /* =================================================
         ADMIN AUTH
      ================================================= */

      if (
        path.startsWith("/api/admin/")
      ) {

        const auth =
          await requireAdmin(
            request,
            env
          );


        /* ===============================================
           SETTINGS
        =============================================== */

        if (
          request.method === "PUT" &&
          path === "/api/admin/settings"
        ) {

          return updateSettings(
            request,
            env,
            auth
          );
        }


        /* ===============================================
           USERS
        =============================================== */

        if (
          request.method === "GET" &&
          path === "/api/admin/users"
        ) {

          return getAdminUsers(
            request,
            env
          );
        }


        const roleMatch =
          path.match(
            /^\/api\/admin\/users\/([^/]+)\/role$/
          );


        if (
          request.method === "PATCH" &&
          roleMatch
        ) {

          return updateUserRole(
            request,
            env,
            auth,
            roleMatch[1]
          );
        }


        const statusMatch =
          path.match(
            /^\/api\/admin\/users\/([^/]+)\/status$/
          );


        if (
          request.method === "PATCH" &&
          statusMatch
        ) {

          return updateUserStatus(
            request,
            env,
            auth,
            statusMatch[1]
          );
        }


        /* ===============================================
           ACADEMIC YEAR
        =============================================== */

        if (
          request.method === "POST" &&
          path === "/api/admin/academic-years"
        ) {

          return createAcademicYear(
            request,
            env,
            auth
          );
        }


        const promoteMatch =
          path.match(
            /^\/api\/admin\/academic-years\/([^/]+)\/promote$/
          );


        if (
          request.method === "POST" &&
          promoteMatch
        ) {

          return promoteAcademicYear(
            request,
            env,
            auth,
            promoteMatch[1]
          );
        }


        /* ===============================================
           CLASSES
        =============================================== */

        if (
          request.method === "POST" &&
          path === "/api/admin/classes"
        ) {

          return createClass(
            request,
            env,
            auth
          );
        }


        /* ===============================================
           SUBJECTS
        =============================================== */

        if (
          request.method === "POST" &&
          path === "/api/admin/subjects"
        ) {

          return createSubject(
            request,
            env,
            auth
          );
        }


        /* ===============================================
           TEACHERS
        =============================================== */

        if (
          request.method === "POST" &&
          path === "/api/admin/teachers"
        ) {

          return createTeacher(
            request,
            env,
            auth
          );
        }


        /* ===============================================
           EXAMS
        =============================================== */

        if (
          request.method === "POST" &&
          path === "/api/admin/exams"
        ) {

          return createExam(
            request,
            env,
            auth
          );
        }


        /* ===============================================
           EXAM SUBJECT
        =============================================== */

        if (
          request.method === "POST" &&
          path === "/api/admin/exam-subjects"
        ) {

          return createExamSubject(
            request,
            env,
            auth
          );
        }


        /* ===============================================
           MARKSHEET CREATE
        =============================================== */

        if (
          request.method === "POST" &&
          path === "/api/admin/marksheets"
        ) {

          return createMarksheet(
            request,
            env,
            auth
          );
        }


        /* ===============================================
           MARKSHEET SUBJECT
        =============================================== */

        const addSubjectMatch =
          path.match(
            /^\/api\/admin\/marksheets\/([^/]+)\/subjects$/
          );


        if (
          request.method === "POST" &&
          addSubjectMatch
        ) {

          return addMarksheetSubject(
            request,
            env,
            auth,
            addSubjectMatch[1]
          );
        }


        /* ===============================================
           SUBJECT MARK UPDATE / DELETE
        =============================================== */

        const subjectRowMatch =
          path.match(
            /^\/api\/admin\/marksheet-subjects\/([^/]+)$/
          );


        if (
          subjectRowMatch &&
          request.method === "PATCH"
        ) {

          return updateMarksheetSubject(
            request,
            env,
            auth,
            subjectRowMatch[1]
          );
        }


        if (
          subjectRowMatch &&
          request.method === "DELETE"
        ) {

          return deleteMarksheetSubject(
            request,
            env,
            auth,
            subjectRowMatch[1]
          );
        }


        /* ===============================================
           MANUAL RANK
        =============================================== */

        const rankMatch =
          path.match(
            /^\/api\/admin\/marksheets\/([^/]+)\/rank$/
          );


        if (
          request.method === "PATCH" &&
          rankMatch
        ) {

          return updateRank(
            request,
            env,
            auth,
            rankMatch[1]
          );
        }


        /* ===============================================
           BOARD RESULT
        =============================================== */

        if (
          request.method === "POST" &&
          path === "/api/admin/results"
        ) {

          return createBoardResult(
            request,
            env,
            auth
          );
        }


        /* ===============================================
           NOTICE
        =============================================== */

        if (
          request.method === "POST" &&
          path === "/api/admin/notices"
        ) {

          return createNotice(
            request,
            env,
            auth
          );
        }


        /* ===============================================
           HERO ADS
        =============================================== */

        if (
          request.method === "POST" &&
          path === "/api/admin/hero-ads"
        ) {

          return createHeroAd(
            request,
            env,
            auth
          );
        }


        /* ===============================================
           EVENTS
        =============================================== */

        if (
          request.method === "POST" &&
          path === "/api/admin/events"
        ) {

          return createEvent(
            request,
            env,
            auth
          );
        }


        /* ===============================================
           GALLERY
        =============================================== */

        if (
          request.method === "POST" &&
          path === "/api/admin/gallery"
        ) {

          return createGallery(
            request,
            env,
            auth
          );
        }


        return error(
          "Admin route not found",
          404,
          request
        );
      }


      /* =================================================
         SINGLE MARKSHEET
      ================================================= */

      const singleMarksheetMatch =
        path.match(
          /^\/api\/marksheets\/([^/]+)$/
        );


      if (
        request.method === "GET" &&
        singleMarksheetMatch
      ) {

        return getSingleMarksheet(
          request,
          env,
          singleMarksheetMatch[1]
        );
      }


      return error(
        "Route not found",
        404,
        request
      );


    } catch (e) {

      console.error(e);


      if (
        e.message ===
        "Authentication required"
      ) {

        return error(
          e.message,
          401,
          request
        );
      }


      if (
        e.message ===
        "Admin access required"
      ) {

        return error(
          e.message,
          403,
          request
        );
      }


      if (
        e.message.includes(
          "Firebase"
        )
      ) {

        return error(
          "Invalid or expired Firebase token",
          401,
          request
        );
      }


      return error(
        e.message ||
          "Internal Server Error",
        500,
        request
      );
    }
  }
};
