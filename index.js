const express = require("express");
const dotenv = require("dotenv");
const { Client } = require("pg");
const bcrypt = require("bcrypt");

//config inicial
const app = express();
dotenv.config();

const PORT = process.env.PORT;

app.use(express.json());

//configuração do banco de dados

const db = new Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

//conectando com o banco de dados

db.connect()
  .then(async () => {
    console.log("Conectando com o banco...");
    console.log("criando tabelas...");

    await db.query(`
    
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL,
            title VARCHAR(200) NOT NULL,
            description TEXT,
            completed BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
        )
    `);

    console.log("Banco conectado e tabelas criadas com sucesso!");
  })
  .catch((error) => {
    console.error("Erro ao conectar com o banco", error);
  });

// ----- ROTAS DE AUTENTICAÇÃO -------

app.post("/api/auth/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res
      .status(400)
      .json({ message: "name, email e password são obrigatórios" });
  }

  try {
    //Verifica se o email existe no banco
    const emailExists = await db.query(`SELECT * FROM users WHERE email = $1`, [
      email,
    ]);

    if (emailExists.rows.length > 0) {
      res.status(400).json({ message: "Email já cadastrado no sistema" });
    }

    const hashPassword = await bcrypt.hash(password, 10);

    const result = await db.query(
      `INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email`,
      [name, email, hashPassword]
    );

    res.status(201).json({
      message: "Usuário criado com sucesso",
      user: result.rows[0],
    });
  } catch (error) {
    console.error(error);
    res.status(400).json({ message: "Erro ao criar o usuário" }, error);
  }
});

// Criando o servidor da API

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
