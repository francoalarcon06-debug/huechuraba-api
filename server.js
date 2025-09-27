import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcryptjs"; // por si después usas contraseñas hasheadas
import crypto from "crypto";    // <-- NUEVO: para generar tokens

dotenv.config();
const { Pool } = pkg;

const app = express();

// CORS (ajusta el origen a tu web en producción)
const ALLOW_ORIGIN = process.env.CORS_ORIGIN || "*";
app.use(cors({ origin: ALLOW_ORIGIN, credentials: true }));

app.use(express.json());

// Conexión a Postgres
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // si tu servidor requiere ssl:
  // ssl: { rejectUnauthorized: false }
});

// (opcional) base de la web para armar links de verificación
const WEB_BASE = process.env.WEB_BASE || "https://web.proyectosfranco.cl";

// Salud
app.get("/health", (req, res) => {
  res.json({ ok: true, service: "huechuraba-api" });
});

// ===================================================================
// Login Personal Municipal (SIN CAMBIOS)
// ===================================================================
app.post("/auth/login", async (req, res) => {
  try {
    const { correo, contrasenia } = req.body; // "contrasenia" en JSON
    if (!correo || !contrasenia) {
      return res.status(400).json({ ok: false, error: "Faltan datos" });
    }

    const q = `
      SELECT
        id,
        correo,
        "contraseña" AS password,
        nombre,
        rut,
        cargo,
        departamento,
        telefono,
        activo
      FROM public.personal_municipalidad
      WHERE LOWER(correo) = $1
      LIMIT 1
    `;
    const { rows } = await pool.query(q, [correo.toLowerCase()]);
    const user = rows[0];

    if (!user || user.activo === false) {
      return res.status(401).json({ ok: false, error: "Credenciales inválidas" });
    }

    const stored = String(user.password || "");
    const plain = String(contrasenia);

    // Soporta texto plano o hash bcrypt (por si migras más adelante)
    let valid = false;
    if (stored.startsWith("$2a$") || stored.startsWith("$2b$") || stored.startsWith("$2y$")) {
      valid = await bcrypt.compare(plain, stored);
    } else {
      valid = stored === plain;
    }

    if (!valid) {
      return res.status(401).json({ ok: false, error: "Credenciales inválidas" });
    }

    // (Opcional) firma JWT, por ahora devuelvo datos simples
    return res.json({
      ok: true,
      user: {
        id: user.id,
        nombre: user.nombre,
        correo: user.correo,
        rut: user.rut,
        cargo: user.cargo,
        departamento: user.departamento
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: "Error de servidor" });
  }
});

// ===================================================================
// NUEVO: Registro de Ciudadanía
//  - Inserta o actualiza no-verificados, genera token y expiración (24h)
//  - Por ahora, devuelve verifyLink (útil mientras no se envía correo real)
// ===================================================================
app.post("/citizens/register", async (req, res) => {
  try {
    const { correo, contrasenia, nombre, telefono } = req.body;

    if (!correo || !contrasenia || !nombre || !telefono) {
      return res.status(400).json({ ok: false, error: "Faltan datos" });
    }

    // Teléfono: 569XXXXXXXX
    if (!/^569\d{8}$/.test(String(telefono))) {
      return res
        .status(400)
        .json({ ok: false, error: "Teléfono inválido. Usa el formato 569XXXXXXXX" });
    }

    // ¿Existe ya?
    const { rows: exist } = await pool.query(
      `SELECT id, verificado FROM public.ciudadanos WHERE correo = $1 LIMIT 1`,
      [correo]
    );
    if (exist.length && exist[0].verificado) {
      return res.status(409).json({ ok: false, error: "Ese correo ya está registrado" });
    }

    // hash de contraseña
    const hash = await bcrypt.hash(String(contrasenia), 10);

    // token y expiración (24h)
    const token = crypto.randomBytes(24).toString("hex");
    const expiracionHoras = 24;

    if (exist.length) {
      // Ya existía sin verificar → reemitimos token y actualizamos datos
      await pool.query(
        `UPDATE public.ciudadanos
         SET contrasenia = $1,
             nombre = $2,
             telefono = $3,
             verificacion_token = $4,
             verificacion_expira = NOW() + INTERVAL '${expiracionHoras} hours'
         WHERE id = $5`,
        [hash, nombre, telefono, token, exist[0].id]
      );
    } else {
      // Nuevo registro
      await pool.query(
        `INSERT INTO public.ciudadanos
         (correo, contrasenia, nombre, telefono, verificado, verificacion_token, verificacion_expira)
         VALUES ($1,$2,$3,$4,false,$5, NOW() + INTERVAL '${expiracionHoras} hours')`,
        [correo, hash, nombre, telefono, token]
      );
    }

    const verifyLink = `${WEB_BASE}/verify.html?token=${token}`;
    console.log("LINK DE VERIFICACIÓN (para pruebas):", verifyLink);

    return res.json({
      ok: true,
      message: "Registro recibido. Revisa tu correo para verificar la cuenta.",
      verifyLink // útil mientras aún no enviamos email real
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: "Error de servidor" });
  }
});

// ===================================================================
// NUEVO: Verificar Ciudadanía (usado por verify.html)
// GET /citizens/verify?token=xxxxx
// ===================================================================
app.get("/citizens/verify", async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) {
      return res.status(400).json({ ok: false, error: "Falta token" });
    }

    const { rowCount } = await pool.query(
      `UPDATE public.ciudadanos
       SET verificado = true,
           verificacion_token = NULL,
           verificacion_expira = NULL
       WHERE verificacion_token = $1
         AND verificacion_expira > NOW()`,
      [token]
    );

    if (rowCount !== 1) {
      return res.status(400).json({ ok: false, error: "Token inválido o expirado" });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: "Error de servidor" });
  }
});

// ===================================================================
// NUEVO: Login de Ciudadanía
//  - Acepta contraseñas en hash o texto plano (por compatibilidad)
// ===================================================================
app.post("/citizens/login", async (req, res) => {
  try {
    const { correo, contrasenia } = req.body;
    if (!correo || !contrasenia) {
      return res.status(400).json({ ok: false, error: "Faltan datos" });
    }

    const { rows } = await pool.query(
      `SELECT id, correo, contrasenia, nombre, telefono, verificado
       FROM public.ciudadanos
       WHERE correo = $1
       LIMIT 1`,
      [correo]
    );
    const user = rows[0];
    if (!user) {
      return res.status(401).json({ ok: false, error: "Credenciales inválidas" });
    }
    if (!user.verificado) {
      return res.status(403).json({ ok: false, error: "Cuenta no verificada" });
    }

    const stored = String(user.contrasenia || "");
    const plain = String(contrasenia);
    let valid = false;

    if (stored.startsWith("$2a$") || stored.startsWith("$2b$") || stored.startsWith("$2y$")) {
      valid = await bcrypt.compare(plain, stored);
    } else {
      valid = stored === plain; // compatibilidad si existen filas antiguas en texto plano
    }

    if (!valid) {
      return res.status(401).json({ ok: false, error: "Credenciales inválidas" });
    }

    return res.json({
      ok: true,
      user: {
        id: user.id,
        nombre: user.nombre,
        correo: user.correo,
        telefono: user.telefono
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: "Error de servidor" });
  }
});

// Puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API escuchando en puerto ${PORT}`);
});

