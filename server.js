const crypto = require("crypto");
const express = require("express");
const fs = require("fs");
const helmet = require("helmet");
const path = require("path");
const sqlite3 = require("sqlite3");

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data", "megasena.db");
const API_URL =
  "https://servicebus2.caixa.gov.br/portaldeloterias/api/megasena/";
const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS || 300000);
const SHARE_BASE_URL = process.env.SHARE_BASE_URL || "https://bolao.bru.to";
const ADMIN_USER = process.env.ADMIN_USER || "atcasanova";
const ADMIN_PASS = process.env.ADMIN_PASS || "atcasanova123atcasanova";

const app = express();
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "https://cdn.jsdelivr.net"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'", "https://servicebus2.caixa.gov.br"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
  })
);
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
        edit_token TEXT NOT NULL,
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

function ensureColumnExists(table, column, definition, onComplete) {
  db.all(`PRAGMA table_info(${table})`, (err, rows) => {
    if (err) {
      console.error(`Falha ao ler schema de ${table}:`, err);
      return;
    }
    const exists = rows.some((row) => row.name === column);
    if (!exists) {
      db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`, () => {
        if (onComplete) onComplete();
      });
      return;
    }
    if (onComplete) onComplete();
  });
}

function backfillEditTokens() {
  db.all(
    "SELECT id FROM boloes WHERE edit_token IS NULL OR edit_token = ''",
    (err, rows) => {
      if (err) {
        console.error("Falha ao gerar tokens de edição:", err);
        return;
      }
      rows.forEach((row) => {
        const token = crypto.randomBytes(16).toString("hex");
        db.run("UPDATE boloes SET edit_token = ? WHERE id = ?", [
          token,
          row.id,
        ]);
      });
    }
  );
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  return header.split(";").reduce((acc, part) => {
    const [name, ...value] = part.trim().split("=");
    if (!name) return acc;
    acc[name] = decodeURIComponent(value.join("="));
    return acc;
  }, {});
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function isAuthorizedForBolao(req, bolao) {
  const cookies = parseCookies(req);
  const cookieToken = cookies[`bolao_admin_${bolao.id}`];
  const queryToken = req.query.token;
  return (
    (cookieToken && cookieToken === bolao.edit_token) ||
    (queryToken && queryToken === bolao.edit_token)
  );
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || "";
  const [, encoded] = header.split(" ");
  const decoded = encoded ? Buffer.from(encoded, "base64").toString() : "";
  const [user, pass] = decoded.split(":");
  if (user === ADMIN_USER && pass === ADMIN_PASS) {
    return next();
  }
  res.setHeader("WWW-Authenticate", 'Basic realm="Admin"');
  res.status(401).send(renderLayout("Admin", "Autenticação necessária."));
}

function renderLayout(title, body) {
  return `<!doctype html>
<html lang="pt-BR">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)}</title>
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

function isValidBolaoId(value) {
  return /^[a-f0-9]{10}$/i.test(value);
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

function parseDrawNumber(input) {
  const drawNumber = Number(input);
  if (!Number.isInteger(drawNumber) || drawNumber < 1 || drawNumber > 9999) {
    return { error: "Número do concurso inválido." };
  }
  return { drawNumber };
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
                <input class="form-control" name="drawNumber" type="number" min="1" max="9999" step="1" inputmode="numeric" required />
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
  const { drawNumber, error } = parseDrawNumber(req.body.drawNumber);
  if (error) {
    return res
      .status(400)
      .send(renderLayout("Erro", escapeHtml(error)));
  }
  const id = generateBolaoId();
  const editToken = crypto.randomBytes(16).toString("hex");
  const createdAt = new Date().toISOString();
  db.run(
    "INSERT INTO boloes (id, draw_number, edit_token, created_at) VALUES (?, ?, ?, ?)",
    [id, drawNumber, editToken, createdAt],
    (err) => {
      if (err) {
        return res
          .status(500)
          .send(renderLayout("Erro", "Não foi possível criar o bolão."));
      }
      res.redirect(`/b/${id}?token=${editToken}`);
    }
  );
});

app.get("/b/:id", async (req, res) => {
  const { id } = req.params;
  if (!isValidBolaoId(id)) {
    return res
      .status(404)
      .send(renderLayout("Bolão", "Bolão não encontrado."));
  }
  db.get(
    "SELECT id, draw_number, edit_token FROM boloes WHERE id = ?",
    [id],
    async (err, bolao) => {
      if (err || !bolao) {
        return res
          .status(404)
          .send(renderLayout("Bolão", "Bolão não encontrado."));
      }
      const authorized = isAuthorizedForBolao(req, bolao);
      if (req.query.token && req.query.token === bolao.edit_token) {
        const cookieFlags = ["Path=/", "SameSite=Lax", "HttpOnly"];
        if (req.secure || SHARE_BASE_URL.startsWith("https://")) {
          cookieFlags.push("Secure");
        }
        res.setHeader(
          "Set-Cookie",
          `bolao_admin_${bolao.id}=${encodeURIComponent(
            bolao.edit_token
          )}; ${cookieFlags.join("; ")}`
        );
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
                      } me-1">${escapeHtml(num)}</span>`;
                    })
                    .join("");
                  return `<li class="list-group-item d-flex justify-content-between align-items-center flex-wrap">
                    <div>${list}</div>
                    <div>${hitBadge}</div>
                  </li>`;
                })
                .join("")
            : `<li class="list-group-item text-muted">Nenhum jogo cadastrado ainda.</li>`;

          const adminLink = `${SHARE_BASE_URL}/b/${encodeURIComponent(
            id
          )}?token=${encodeURIComponent(bolao.edit_token)}`;
          const shareLink = `${SHARE_BASE_URL}/b/${encodeURIComponent(id)}`;
          const addGameCard = authorized
            ? `
                <div class="card shadow-sm mb-4">
                  <div class="card-body">
                    <h2 class="h6">Adicionar jogo</h2>
                    <form method="post" action="/b/${id}/games">
                      <div class="mb-3">
                        <label class="form-label">Dezenas (6 a 15)</label>
                        <input class="form-control" name="numbers" placeholder="Ex: 01 05 12 23 34 45" pattern="^\\s*\\d{1,2}(?:\\s*[ ,;-]\\s*\\d{1,2})*\\s*$" inputmode="numeric" required />
                        <div class="form-text">Separe por espaço, vírgula ou ponto-e-vírgula.</div>
                      </div>
                      <button class="btn btn-primary w-100">Salvar jogo</button>
                    </form>
                  </div>
                </div>
              `
            : `
                <div class="card border-0 bg-white shadow-sm mb-4">
                  <div class="card-body">
                    <h2 class="h6">Somente leitura</h2>
                    <p class="text-muted mb-0">Apenas o criador do bolão pode cadastrar jogos.</p>
                  </div>
                </div>
              `;

          const body = `
            <div class="d-flex justify-content-between align-items-center mb-3">
              <div>
                <h1 class="h4">Bolão ${escapeHtml(id)}</h1>
                ${resultBadge}
              </div>
              <div>
                <small class="text-muted">Link para compartilhar</small><br />
                <code>${escapeHtml(shareLink)}</code>
                ${
                  authorized
                    ? `<div class="mt-2"><small class="text-muted">Link do administrador</small><br /><code>${escapeHtml(
                        adminLink
                      )}</code></div>`
                    : ""
                }
              </div>
            </div>
            <div class="row">
              <div class="col-lg-4">
                ${addGameCard}
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
  if (!isValidBolaoId(id)) {
    return res
      .status(404)
      .send(renderLayout("Erro", "Bolão não encontrado."));
  }
  db.get(
    "SELECT id, edit_token FROM boloes WHERE id = ?",
    [id],
    (err, bolao) => {
      if (err || !bolao) {
        return res
          .status(404)
          .send(renderLayout("Erro", "Bolão não encontrado."));
      }
      if (!isAuthorizedForBolao(req, bolao)) {
        return res
          .status(403)
          .send(renderLayout("Erro", "Apenas o criador do bolão pode cadastrar jogos."));
      }
      const { numbers, error } = parseNumbers(String(req.body.numbers || ""));
      if (error) {
        return res
          .status(400)
          .send(
            renderLayout(
              "Erro",
              `<p>${escapeHtml(error)}</p><p><a href="/b/${encodeURIComponent(
                id
              )}">Voltar</a></p>`
            )
          );
      }
      db.run(
        "INSERT INTO games (bolao_id, numbers, created_at) VALUES (?, ?, ?)",
        [id, JSON.stringify(numbers), new Date().toISOString()],
        (errInsert) => {
          if (errInsert) {
            return res
              .status(500)
              .send(renderLayout("Erro", "Não foi possível salvar o jogo."));
          }
          res.redirect(`/b/${id}?token=${bolao.edit_token}`);
        }
      );
    }
  );
});

app.get("/admin", requireAdmin, (req, res) => {
  db.all(
    "SELECT id, draw_number, created_at FROM boloes ORDER BY created_at DESC",
    (err, boloes) => {
      if (err) {
        return res
          .status(500)
          .send(renderLayout("Admin", "Falha ao carregar bolões."));
      }
      const list = boloes.length
          ? boloes
            .map((bolao) => {
              const shareLink = `${SHARE_BASE_URL}/b/${encodeURIComponent(
                bolao.id
              )}`;
              return `<li class="list-group-item d-flex flex-column flex-md-row justify-content-between align-items-md-center gap-3">
                <div>
                  <strong>Bolão ${escapeHtml(bolao.id)}</strong><br />
                  <small class="text-muted">Concurso ${escapeHtml(
                    bolao.draw_number
                  )}</small><br />
                  <small class="text-muted">Link: ${escapeHtml(
                    shareLink
                  )}</small>
                </div>
                <div class="d-flex gap-2">
                  <a class="btn btn-sm btn-outline-primary" href="/admin/boloes/${encodeURIComponent(
                    bolao.id
                  )}">Editar</a>
                  <form method="post" action="/admin/boloes/${encodeURIComponent(
                    bolao.id
                  )}/delete">
                    <button class="btn btn-sm btn-outline-danger">Excluir</button>
                  </form>
                </div>
              </li>`;
            })
            .join("")
        : `<li class="list-group-item text-muted">Nenhum bolão cadastrado.</li>`;

      const body = `
        <div class="d-flex justify-content-between align-items-center mb-3">
          <div>
            <h1 class="h4">Área administrativa</h1>
            <p class="text-muted mb-0">Gerencie todos os bolões cadastrados.</p>
          </div>
        </div>
        <div class="card shadow-sm">
          <div class="card-body">
            <ul class="list-group list-group-flush">
              ${list}
            </ul>
          </div>
        </div>
      `;
      res.send(renderLayout("Admin", body));
    }
  );
});

app.get("/admin/boloes/:id", requireAdmin, (req, res) => {
  const { id } = req.params;
  if (!isValidBolaoId(id)) {
    return res
      .status(404)
      .send(renderLayout("Admin", "Bolão não encontrado."));
  }
  db.get(
    "SELECT id, draw_number, edit_token, created_at FROM boloes WHERE id = ?",
    [id],
    (err, bolao) => {
      if (err || !bolao) {
        return res
          .status(404)
          .send(renderLayout("Admin", "Bolão não encontrado."));
      }
      db.all(
        "SELECT id, numbers FROM games WHERE bolao_id = ? ORDER BY id DESC",
        [id],
        (errGames, games) => {
          if (errGames) {
            return res
              .status(500)
              .send(renderLayout("Admin", "Falha ao carregar jogos."));
          }
          const shareLink = `${SHARE_BASE_URL}/b/${encodeURIComponent(
            bolao.id
          )}`;
          const adminLink = `${SHARE_BASE_URL}/b/${encodeURIComponent(
            bolao.id
          )}?token=${encodeURIComponent(bolao.edit_token)}`;
          const gamesHtml = games.length
            ? games
                .map((game) => {
                  const numbers = JSON.parse(game.numbers)
                    .map((num) => escapeHtml(num))
                    .join(" ");
                  return `<li class="list-group-item d-flex justify-content-between align-items-center">
                    <span>${numbers}</span>
                  </li>`;
                })
                .join("")
            : `<li class="list-group-item text-muted">Nenhum jogo cadastrado.</li>`;

          const body = `
            <div class="d-flex justify-content-between align-items-center mb-3">
              <div>
                <h1 class="h4">Administração do bolão ${escapeHtml(
                  bolao.id
                )}</h1>
                <small class="text-muted">Criado em ${escapeHtml(
                  new Date(bolao.created_at).toLocaleString("pt-BR")
                )}</small>
              </div>
              <a class="btn btn-outline-secondary" href="/admin">Voltar</a>
            </div>
            <div class="row g-4">
              <div class="col-lg-4">
                <div class="card shadow-sm mb-4">
                  <div class="card-body">
                    <h2 class="h6">Editar concurso</h2>
                    <form method="post" action="/admin/boloes/${bolao.id}/update">
                      <div class="mb-3">
                        <label class="form-label">Número do concurso</label>
                        <input class="form-control" name="drawNumber" type="number" min="1" max="9999" step="1" inputmode="numeric" value="${escapeHtml(
                          bolao.draw_number
                        )}" required />
                      </div>
                      <button class="btn btn-primary w-100">Salvar alterações</button>
                    </form>
                  </div>
                </div>
                <div class="card shadow-sm mb-4">
                  <div class="card-body">
                    <h2 class="h6">Adicionar jogo</h2>
                    <form method="post" action="/admin/boloes/${bolao.id}/games">
                      <div class="mb-3">
                        <label class="form-label">Dezenas (6 a 15)</label>
                        <input class="form-control" name="numbers" placeholder="Ex: 01 05 12 23 34 45" pattern="^\\s*\\d{1,2}(?:\\s*[ ,;-]\\s*\\d{1,2})*\\s*$" inputmode="numeric" required />
                      </div>
                      <button class="btn btn-outline-primary w-100">Salvar jogo</button>
                    </form>
                  </div>
                </div>
                <div class="card border-0 bg-white shadow-sm">
                  <div class="card-body">
                    <h2 class="h6">Links</h2>
                    <p class="small text-muted mb-2">Compartilhamento:</p>
                    <code class="small">${escapeHtml(shareLink)}</code>
                    <p class="small text-muted mt-3 mb-2">Administrador:</p>
                    <code class="small">${escapeHtml(adminLink)}</code>
                  </div>
                </div>
              </div>
              <div class="col-lg-8">
                <div class="card shadow-sm mb-4">
                  <div class="card-body">
                    <h2 class="h6">Jogos cadastrados</h2>
                    <ul class="list-group list-group-flush">
                      ${gamesHtml}
                    </ul>
                  </div>
                </div>
                <form method="post" action="/admin/boloes/${bolao.id}/delete">
                  <button class="btn btn-danger">Excluir bolão</button>
                </form>
              </div>
            </div>
          `;
          res.send(renderLayout("Admin", body));
        }
      );
    }
  );
});

app.post("/admin/boloes/:id/update", requireAdmin, (req, res) => {
  const { id } = req.params;
  if (!isValidBolaoId(id)) {
    return res
      .status(404)
      .send(renderLayout("Admin", "Bolão não encontrado."));
  }
  const { drawNumber, error } = parseDrawNumber(req.body.drawNumber);
  if (error) {
    return res
      .status(400)
      .send(renderLayout("Admin", escapeHtml(error)));
  }
  db.run(
    "UPDATE boloes SET draw_number = ? WHERE id = ?",
    [drawNumber, id],
    (err) => {
      if (err) {
        return res
          .status(500)
          .send(renderLayout("Admin", "Falha ao atualizar bolão."));
      }
      res.redirect(`/admin/boloes/${id}`);
    }
  );
});

app.post("/admin/boloes/:id/games", requireAdmin, (req, res) => {
  const { id } = req.params;
  if (!isValidBolaoId(id)) {
    return res
      .status(404)
      .send(renderLayout("Admin", "Bolão não encontrado."));
  }
  const { numbers, error } = parseNumbers(String(req.body.numbers || ""));
  if (error) {
    return res
      .status(400)
      .send(
        renderLayout(
          "Admin",
          `<p>${escapeHtml(error)}</p><p><a href="/admin/boloes/${encodeURIComponent(
            id
          )}">Voltar</a></p>`
        )
      );
  }
  db.run(
    "INSERT INTO games (bolao_id, numbers, created_at) VALUES (?, ?, ?)",
    [id, JSON.stringify(numbers), new Date().toISOString()],
    (err) => {
      if (err) {
        return res
          .status(500)
          .send(renderLayout("Admin", "Não foi possível salvar o jogo."));
      }
      res.redirect(`/admin/boloes/${id}`);
    }
  );
});

app.post("/admin/boloes/:id/delete", requireAdmin, (req, res) => {
  const { id } = req.params;
  if (!isValidBolaoId(id)) {
    return res
      .status(404)
      .send(renderLayout("Admin", "Bolão não encontrado."));
  }
  db.serialize(() => {
    db.run("DELETE FROM games WHERE bolao_id = ?", [id], (err) => {
      if (err) {
        return res
          .status(500)
          .send(renderLayout("Admin", "Falha ao excluir jogos do bolão."));
      }
      db.run("DELETE FROM boloes WHERE id = ?", [id], (errDelete) => {
        if (errDelete) {
          return res
            .status(500)
            .send(renderLayout("Admin", "Falha ao excluir bolão."));
        }
        res.redirect("/admin");
      });
    });
  });
});

app.use((req, res) => {
  res.status(404).send(renderLayout("404", "Página não encontrada."));
});

initDb();
ensureColumnExists("boloes", "edit_token", "TEXT", backfillEditTokens);
startPolling();

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
