import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcryptjs"; // por si después usas contraseñas hasheadas

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

// Salud
app.get("/health", (req, res) => {
  res.json({ ok: true, service: "huechuraba-api" });
});

// Login Personal Municipal
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

    // Soporta ambas: texto plano o hash bcrypt (por si migras más adelante)
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

// Puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API escuchando en puerto ${PORT}`);
});
