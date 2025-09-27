import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcryptjs";

dotenv.config();
const { Pool } = pkg;

const app = express();

// CORS (ajusta el origen en producción)
const ALLOW_ORIGIN = process.env.CORS_ORIGIN || "*";
app.use(cors({ origin: ALLOW_ORIGIN, credentials: true }));

app.use(express.json());

// Conexión a Postgres
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Si tu instancia requiere SSL, descomenta:
  // ssl: { rejectUnauthorized: false },
});

// Salud
app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "huechuraba-api" });
});

// Login Personal Municipalidad
app.post("/auth/login", async (req, res) => {
  try {
    const { correo, contrasenia } = req.body; // usamos "contrasenia" en el JSON
    if (!correo || !contrasenia) {
      return res.status(400).json({ ok: false, error: "Faltan datos" });
    }

    // Nota: en la base la columna es "contraseña" (con ñ).
    // Para ser tolerantes si después creas "contrasenia", usamos COALESCE.
    const q = `
      SELECT
        id,
        correo,
        COALESCE("contraseña", contrasenia) AS password,
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

    const stored = String(user.password ?? "");
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

    // Respuesta simple (si luego quieres JWT lo agregamos)
    return res.json({
      ok: true,
      user: {
        id: user.id,
        nombre: user.nombre,
        correo: user.correo,
        rut: user.rut,
        cargo: user.cargo,
        departamento: user.departamento,
      },
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
