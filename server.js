import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcryptjs"; // lo dejamos para PM por compatibilidad

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
  // ssl: { rejectUnauthorized: false } // si tu server lo requiere
});

// Salud
app.get("/health", (req, res) => {
  res.json({ ok: true, service: "huechuraba-api" });
});

/* =========================================================
   LOGIN: PERSONAL MUNICIPAL (se mantiene igual que tenías)
   ========================================================= */
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

    // Soporta texto plano o hash bcrypt
    let valid = false;
    if (stored.startsWith("$2a$") || stored.startsWith("$2b$") || stored.startsWith("$2y$")) {
      valid = await bcrypt.compare(plain, stored);
    } else {
      valid = stored === plain;
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

/* =========================================================
   NUEVO: CIUDADANOS (simple, sin verificación por correo)
   ========================================================= */

/** Login Ciudadanos: compara en texto plano (prototipo) */
app.post("/ciudadanos/login", async (req, res) => {
  try {
    const { correo, contrasenia } = req.body;
    if (!correo || !contrasenia) {
      return res.status(400).json({ ok: false, error: "Faltan datos" });
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
      return res.status(401).json({ ok: false, error: "Credenciales inválidas" });
    }

    // Prototipo: comparación en texto plano
    if (String(user.contrasenia) !== String(contrasenia)) {
      return res.status(401).json({ ok: false, error: "Credenciales inválidas" });
    }

    if (user.verificado === false) {
      return res.status(403).json({ ok: false, error: "Cuenta no verificada" });
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

/** Registro Ciudadanos: guarda password tal cual y verificado=true por defecto */
app.post("/ciudadanos/register", async (req, res) => {
  try {
    const { nombre, correo, telefono, contrasenia } = req.body;

    if (!nombre || !correo || !telefono || !contrasenia) {
      return res.status(400).json({ ok: false, error: "Faltan datos" });
    }

    // Validación simple de teléfono: 12 dígitos y empiece por 569
    if (!/^569\d{8}$/.test(String(telefono))) {
      return res.status(400).json({ ok: false, error: "Teléfono inválido (usa formato 569XXXXXXXX)" });
    }

    // Insert (verificado por defecto TRUE, y correo único)
    const q = `
      INSERT INTO public.ciudadanos (correo, contrasenia, nombre, telefono, verificado)
      VALUES ($1, $2, $3, $4, TRUE)
      RETURNING id, correo, nombre, telefono
    `;
    try {
      const { rows } = await pool.query(q, [
        correo.toLowerCase(),
        contrasenia, // PROTOTIPO: sin hash
        nombre,
        telefono
      ]);
      const user = rows[0];

      return res.json({
        ok: true,
        user: {
          id: user.id,
          nombre: user.nombre,
          correo: user.correo,
          telefono: user.telefono
        },
        message: "Registro completado"
      });
    } catch (e) {
      // Si viola la restricción única del correo
      if (String(e?.message || "").toLowerCase().includes("unique")) {
        return res.status(409).json({ ok: false, error: "Este correo ya está registrado" });
      }
      throw e;
    }
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
