const crypto = require("crypto");
const express = require("express");
const fs = require("fs");
const path = require("path");
const sqlite3 = require("sqlite3");

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data", "megasena.db");
const API_URL =
  "https://servicebus2.caixa.gov.br/portaldeloterias/api/megasena/";
const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS || 300000);

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new sqlite3.Database(DB_PATH);

function initDb() {
  db.serialize(() => {
    db.run(
      `CREATE TABLE IF NOT EXISTS boloes (
        id TEXT PRIMARY KEY,
        draw_number INTEGER NOT NULL,
        created_at TEXT NOT NULL
      )`
    );
    db.run(
      `CREATE TABLE IF NOT EXISTS games (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bolao_id TEXT NOT NULL,
        numbers TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (bolao_id) REFERENCES boloes(id)
      )`
    );
    db.run(
      `CREATE TABLE IF NOT EXISTS draws (
        number INTEGER PRIMARY KEY,
        numbers TEXT NOT NULL,
        draw_date TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`
    );
  });
}

function renderLayout(title, body) {
  return `<!doctype html>
<html lang="pt-BR">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${title}</title>
    <link
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"
      rel="stylesheet"
    />
  </head>
  <body class="bg-light">
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary mb-4">
      <div class="container">
        <a class="navbar-brand" href="/">Bolão Mega-Sena</a>
      </div>
    </nav>
    <main class="container">${body}</main>
  </body>
</html>`;
}

function generateBolaoId() {
  return crypto.randomBytes(5).toString("hex");
}

function parseNumbers(input) {
  const tokens = input
    .replace(/[^0-9\s,;-]/g, " ")
    .split(/[\s,;-]+/)
    .filter(Boolean)
    .map((value) => Number(value));

  const unique = [...new Set(tokens)];
  if (unique.length < 6 || unique.length > 15) {
    return { error: "Informe entre 6 e 15 dezenas." };
  }
  if (unique.some((value) => Number.isNaN(value))) {
    return { error: "Use apenas números." };
  }
  if (unique.some((value) => value < 1 || value > 60)) {
    return { error: "As dezenas devem estar entre 1 e 60." };
  }
  return {
    numbers: unique
      .sort((a, b) => a - b)
      .map((value) => String(value).padStart(2, "0")),
  };
}

function fetchLatestDraw() {
  return fetch(API_URL)
    .then((res) => res.json())
    .then((data) => {
      if (!data || !data.numero || !data.listaDezenas) {
        throw new Error("Resposta inválida da API");
      }
      const numbers = data.listaDezenas
        .map((value) => String(value).padStart(2, "0"))
        .sort();
      return {
        number: data.numero,
        numbers,
        drawDate: data.dataApuracao,
      };
    });
}

function storeDraw(draw) {
  const now = new Date().toISOString();
  db.run(
    `INSERT INTO draws (number, numbers, draw_date, updated_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(number) DO UPDATE SET
       numbers = excluded.numbers,
       draw_date = excluded.draw_date,
       updated_at = excluded.updated_at`,
    [draw.number, JSON.stringify(draw.numbers), draw.drawDate, now]
  );
}

function startPolling() {
  const poll = () => {
    fetchLatestDraw()
      .then((draw) => storeDraw(draw))
      .catch((err) => console.error("Falha ao buscar concurso:", err));
  };
  poll();
  setInterval(poll, POLL_INTERVAL_MS);
}

function getDraw(number) {
  return new Promise((resolve, reject) => {
    db.get(
      "SELECT number, numbers, draw_date FROM draws WHERE number = ?",
      [number],
      (err, row) => {
        if (err) return reject(err);
        if (!row) return resolve(null);
        resolve({
          number: row.number,
          numbers: JSON.parse(row.numbers),
          drawDate: row.draw_date,
        });
      }
    );
  });
}

app.get("/", (req, res) => {
  const body = `
    <div class="row">
      <div class="col-lg-8">
        <div class="card shadow-sm">
          <div class="card-body">
            <h1 class="h4">Criar novo bolão</h1>
            <p class="text-muted">Informe o número do concurso e cadastre seus jogos.</p>
            <form method="post" action="/bolao">
              <div class="mb-3">
                <label class="form-label">Número do concurso</label>
                <input class="form-control" name="drawNumber" type="number" min="1" required />
              </div>
              <button class="btn btn-primary">Criar bolão</button>
            </form>
          </div>
        </div>
      </div>
      <div class="col-lg-4 mt-4 mt-lg-0">
        <div class="card border-0 bg-white shadow-sm">
          <div class="card-body">
            <h2 class="h6">Como funciona</h2>
            <ol class="small text-muted">
              <li>Crie o bolão com o número do concurso.</li>
              <li>Cadastre jogos com 6 a 15 dezenas.</li>
              <li>Compartilhe o link com os amigos.</li>
              <li>O sistema confere automaticamente quando o concurso sair.</li>
            </ol>
          </div>
        </div>
      </div>
    </div>
  `;
  res.send(renderLayout("Bolão Mega-Sena", body));
});

app.post("/bolao", (req, res) => {
  const drawNumber = Number(req.body.drawNumber);
  if (!drawNumber || Number.isNaN(drawNumber)) {
    return res
      .status(400)
      .send(renderLayout("Erro", "Número do concurso inválido."));
  }
  const id = generateBolaoId();
  const createdAt = new Date().toISOString();
  db.run(
    "INSERT INTO boloes (id, draw_number, created_at) VALUES (?, ?, ?)",
    [id, drawNumber, createdAt],
    (err) => {
      if (err) {
        return res
          .status(500)
          .send(renderLayout("Erro", "Não foi possível criar o bolão."));
      }
      res.redirect(`/b/${id}`);
    }
  );
});

app.get("/b/:id", async (req, res) => {
  const { id } = req.params;
  db.get(
    "SELECT id, draw_number FROM boloes WHERE id = ?",
    [id],
    async (err, bolao) => {
      if (err || !bolao) {
        return res
          .status(404)
          .send(renderLayout("Bolão", "Bolão não encontrado."));
      }
      db.all(
        "SELECT id, numbers FROM games WHERE bolao_id = ? ORDER BY id DESC",
        [id],
        async (errGames, games) => {
          if (errGames) {
            return res
              .status(500)
              .send(renderLayout("Erro", "Falha ao carregar jogos."));
          }
          const draw = await getDraw(bolao.draw_number);
          const drawNumbers = draw ? new Set(draw.numbers) : null;
          const resultBadge = draw
            ? `<span class="badge bg-success">Concurso ${draw.number} (${draw.drawDate})</span>`
            : `<span class="badge bg-warning text-dark">Aguardando concurso ${bolao.draw_number}</span>`;

          const gamesHtml = games.length
            ? games
                .map((game) => {
                  const numbers = JSON.parse(game.numbers);
                  const hits = drawNumbers
                    ? numbers.filter((num) => drawNumbers.has(num))
                    : [];
                  const hitCount = hits.length;
                  const hitBadge = drawNumbers
                    ? `<span class="badge bg-${
                        hitCount >= 6
                          ? "success"
                          : hitCount >= 4
                          ? "primary"
                          : "secondary"
                      } ms-2">${hitCount} acertos</span>`
                    : `<span class="badge bg-secondary ms-2">--</span>`;

                  const list = numbers
                    .map((num) => {
                      const active = drawNumbers && drawNumbers.has(num);
                      return `<span class="badge rounded-pill ${
                        active ? "bg-success" : "bg-light text-dark"
                      } me-1">${num}</span>`;
                    })
                    .join("");
                  return `<li class="list-group-item d-flex justify-content-between align-items-center flex-wrap">
                    <div>${list}</div>
                    <div>${hitBadge}</div>
                  </li>`;
                })
                .join("")
            : `<li class="list-group-item text-muted">Nenhum jogo cadastrado ainda.</li>`;

          const body = `
            <div class="d-flex justify-content-between align-items-center mb-3">
              <div>
                <h1 class="h4">Bolão ${id}</h1>
                ${resultBadge}
              </div>
              <div>
                <small class="text-muted">Link para compartilhar</small><br />
                <code>${req.protocol}://${req.get("host")}/b/${id}</code>
              </div>
            </div>
            <div class="row">
              <div class="col-lg-4">
                <div class="card shadow-sm mb-4">
                  <div class="card-body">
                    <h2 class="h6">Adicionar jogo</h2>
                    <form method="post" action="/b/${id}/games">
                      <div class="mb-3">
                        <label class="form-label">Dezenas (6 a 15)</label>
                        <input class="form-control" name="numbers" placeholder="Ex: 01 05 12 23 34 45" required />
                        <div class="form-text">Separe por espaço, vírgula ou ponto-e-vírgula.</div>
                      </div>
                      <button class="btn btn-primary w-100">Salvar jogo</button>
                    </form>
                  </div>
                </div>
              </div>
              <div class="col-lg-8">
                <div class="card shadow-sm">
                  <div class="card-body">
                    <h2 class="h6">Jogos cadastrados</h2>
                    <ul class="list-group list-group-flush">
                      ${gamesHtml}
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          `;
          res.send(renderLayout(`Bolão ${id}`, body));
        }
      );
    }
  );
});

app.post("/b/:id/games", (req, res) => {
  const { id } = req.params;
  const { numbers, error } = parseNumbers(String(req.body.numbers || ""));
  if (error) {
    return res
      .status(400)
      .send(renderLayout("Erro", `<p>${error}</p><p><a href="/b/${id}">Voltar</a></p>`));
  }
  db.run(
    "INSERT INTO games (bolao_id, numbers, created_at) VALUES (?, ?, ?)",
    [id, JSON.stringify(numbers), new Date().toISOString()],
    (err) => {
      if (err) {
        return res
          .status(500)
          .send(renderLayout("Erro", "Não foi possível salvar o jogo."));
      }
      res.redirect(`/b/${id}`);
    }
  );
});

app.use((req, res) => {
  res.status(404).send(renderLayout("404", "Página não encontrada."));
});

initDb();
startPolling();

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
