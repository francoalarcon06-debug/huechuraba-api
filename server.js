import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
// import bcrypt from "bcryptjs"; // no lo usamos en el prototipo (guardamos plano)

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
  // ssl: { rejectUnauthorized: false } // solo si tu servidor lo requiere
});

// Salud
app.get("/health", (req, res) => {
  res.json({ ok: true, service: "huechuraba-api" });
});

/* =========================================================
   LOGIN: Personal Municipal (SE MANTIENE IGUAL)
   ========================================================= */
app.post("/auth/login", async (req, res) => {
  try {
    const { correo, contrasenia } = req.body; // "contrasenia" en JSON
    if (!correo || !contrasenia) {
      return res.status(400).json({ ok: false, error: "faltan_datos" });
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
      return res.status(401).json({ ok: false, error: "credenciales_invalidas" });
    }

    // En PM comparamos plano por ahora
    const stored = String(user.password || "");
    const plain = String(contrasenia);

    const valid = stored === plain;

    if (!valid) {
      return res.status(401).json({ ok: false, error: "credenciales_invalidas" });
    }

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
    return res.status(500).json({ ok: false, error: "error_servidor" });
  }
});

/* =========================================================
   LOGIN: Ciudadanía (PLANO y verificado=true)
   Tabla: public.ciudadanos
   Columnas que usamos: id, correo (citext), contrasenia (varchar),
                        nombre, telefono, verificado (boolean)
   ========================================================= */
app.post("/auth/login-ciudadano", async (req, res) => {
  try {
    const { correo, contrasenia } = req.body;
    if (!correo || !contrasenia) {
      return res.status(400).json({ ok: false, error: "faltan_datos" });
    }

    const q = `
      SELECT id, correo, contrasenia, nombre, telefono, verificado
      FROM public.ciudadanos
      WHERE LOWER(correo) = $1
      LIMIT 1
    `;
    const { rows } = await pool.query(q, [correo.toLowerCase()]);
    const user = rows[0];

    if (!user) {
      return res.status(401).json({ ok: false, error: "credenciales_invalidas" });
    }

    // En el prototipo: contrasenia en texto plano
    if (String(user.contrasenia || "") !== String(contrasenia)) {
      return res.status(401).json({ ok: false, error: "credenciales_invalidas" });
    }

    if (!user.verificado) {
      return res.status(403).json({ ok: false, error: "no_verificado" });
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
    return res.status(500).json({ ok: false, error: "error_servidor" });
  }
});

/* =========================================================
   REGISTRO: Ciudadanía (PLANO + verificado=true por default)
   Reglas:
   - teléfono: /^569\d{8}$/ (12 caracteres, 569 + 8 dígitos)
   - correo único (citext en DB ayuda; igual revisamos antes)
   - si ya existe => 409 correo_ya_registrado
   ========================================================= */
app.post("/ciudadanos/register", async (req, res) => {
  try {
    const { nombre, correo, telefono, contrasenia } = req.body;

    if (!nombre || !correo || !telefono || !contrasenia) {
      return res.status(400).json({ ok: false, error: "faltan_datos" });
    }

    const tel = String(telefono).trim();
    const reTel = /^569\d{8}$/; // 569 + 8 dígitos
    if (!reTel.test(tel)) {
      return res.status(400).json({ ok: false, error: "telefono_invalido", esperado: "569XXXXXXXX" });
    }

    const email = String(correo).trim().toLowerCase();

    // ¿Ya existe?
    const qExists = `SELECT id FROM public.ciudadanos WHERE LOWER(correo) = $1 LIMIT 1`;
    const { rows: ex } = await pool.query(qExists, [email]);
    if (ex.length > 0) {
      return res.status(409).json({ ok: false, error: "correo_ya_registrado" });
    }

    // Insertamos en plano y verificado=true (prototipo)
    const qIns = `
      INSERT INTO public.ciudadanos (correo, contrasenia, nombre, telefono, verificado)
      VALUES ($1, $2, $3, $4, true)
      RETURNING id, correo, nombre, telefono, verificado
    `;
    const { rows } = await pool.query(qIns, [email, contrasenia, nombre, tel]);
    const user = rows[0];

    return res.status(201).json({ ok: true, user });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: "error_servidor" });
  }
});

// Puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API escuchando en puerto ${PORT}`);
});
