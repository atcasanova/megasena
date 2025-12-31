process.env.TZ = "America/Sao_Paulo";

const crypto = require("crypto");
const express = require("express");
const fs = require("fs");
const helmet = require("helmet");
const nodemailer = require("nodemailer");
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
const SMTP_HOST = process.env.SMTP_HOST || "127.0.0.1";
const SMTP_PORT = Number(process.env.SMTP_PORT || 25);
const FROM_DOMAIN = process.env.FROM_DOMAIN || "bru.to";
const SMTP_SECURE =
  SMTP_PORT === 25 ? false : process.env.SMTP_SECURE === "true";
const SMTP_IGNORE_TLS = process.env.SMTP_IGNORE_TLS === "true";
const SMTP_REQUIRE_TLS = process.env.SMTP_REQUIRE_TLS === "true";
const SMTP_TLS_REJECT_UNAUTHORIZED =
  process.env.SMTP_TLS_REJECT_UNAUTHORIZED !== "false";

const mailTransportOptions = {
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_SECURE,
  ...(SMTP_IGNORE_TLS ? { ignoreTLS: true } : {}),
  ...(SMTP_REQUIRE_TLS ? { requireTLS: true } : {}),
  ...(!SMTP_TLS_REJECT_UNAUTHORIZED
    ? { tls: { rejectUnauthorized: false } }
    : {}),
};

const mailTransport = nodemailer.createTransport(mailTransportOptions);

console.log("SMTP config:", {
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_SECURE,
  ignoreTLS: SMTP_IGNORE_TLS,
  requireTLS: SMTP_REQUIRE_TLS,
  rejectUnauthorized: SMTP_TLS_REJECT_UNAUTHORIZED,
});

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
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new sqlite3.Database(DB_PATH);

function logAction(message, details = {}) {
  const payload = Object.keys(details).length ? ` | ${JSON.stringify(details)}` : "";
  console.log(`[bolao] ${message}${payload}`);
}

function initDb() {
  db.serialize(() => {
    db.run(
      `CREATE TABLE IF NOT EXISTS boloes (
        id TEXT PRIMARY KEY,
        name TEXT,
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
    db.run(
      `CREATE TABLE IF NOT EXISTS bolao_subscribers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bolao_id TEXT NOT NULL,
        email TEXT NOT NULL,
        status TEXT NOT NULL,
        verification_token TEXT,
        created_at TEXT NOT NULL,
        verified_at TEXT,
        last_notified_draw INTEGER,
        UNIQUE(bolao_id, email),
        FOREIGN KEY (bolao_id) REFERENCES boloes(id)
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

function parseBolaoName(input) {
  const name = String(input || "").trim();
  if (!name) {
    return { name: "" };
  }
  if (name.length > 80) {
    return { error: "O nome do bolão deve ter até 80 caracteres." };
  }
  return { name };
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

function getBolaoDisplayName(bolao) {
  const name = String(bolao.name || "").trim();
  if (name) {
    return `Bolão ${name}`;
  }
  return `Bolão ${bolao.id}`;
}

function getGameStats(games, drawNumbersSet) {
  return games.map((game) => {
    const numbers = JSON.parse(game.numbers);
    const hitCount = drawNumbersSet
      ? numbers.filter((num) => drawNumbersSet.has(num)).length
      : 0;
    return {
      game,
      numbers,
      hitCount,
      size: numbers.length,
    };
  });
}

function sortGameStats(stats, hasDraw) {
  return [...stats].sort((a, b) => {
    if (hasDraw && b.hitCount !== a.hitCount) {
      return b.hitCount - a.hitCount;
    }
    if (b.size !== a.size) {
      return b.size - a.size;
    }
    return b.game.id - a.game.id;
  });
}

function getMaxHits(stats) {
  return stats.reduce((max, game) => Math.max(max, game.hitCount), 0);
}

function getHitAchievement(hitCount) {
  if (hitCount === 6) {
    return {
      label: "sena",
      title: "Você acertou a sena!",
      emoji: "🏆",
      highlight: "background:#ecfdf3;border:2px solid #22c55e;",
      emphasis: "font-size:16px;font-weight:700;",
    };
  }
  if (hitCount === 5) {
    return {
      label: "quina",
      title: "Você acertou a quina!",
      emoji: "🥳",
      highlight: "background:#fef9c3;border:2px solid #eab308;",
      emphasis: "font-size:15px;font-weight:700;",
    };
  }
  if (hitCount === 4) {
    return {
      label: "quadra",
      title: "Você acertou a quadra!",
      emoji: "🎉",
      highlight: "background:#fffbeb;border:2px solid #f59e0b;",
      emphasis: "font-size:14px;font-weight:600;",
    };
  }
  return null;
}

function renderLayout(title, body, extraHead = "") {
  return `<!doctype html>
<html lang="pt-BR">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)}</title>
    <link rel="icon" href="/favico.ico" type="image/x-icon">
    ${extraHead}
    <link
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"
      rel="stylesheet"
    />
    <style>
      body {
        background: radial-gradient(circle at top, #eef2ff 0%, #f8fafc 45%, #ffffff 100%);
      }
      .navbar {
        background: linear-gradient(120deg, #2563eb 0%, #1d4ed8 55%, #1e40af 100%);
        box-shadow: 0 10px 24px rgba(30, 64, 175, 0.2);
      }
      .card {
        border: 0;
        border-radius: 18px;
        box-shadow: 0 14px 30px rgba(15, 23, 42, 0.08);
      }
      .card-header,
      .card-body {
        border-radius: 18px;
      }
      .link-box {
        background: #f1f5f9;
        border-radius: 12px;
        padding: 10px 12px;
        color: #0f172a;
        word-break: break-all;
      }
      .share-panel {
        background: #ffffff;
        border: 1px solid rgba(148, 163, 184, 0.3);
        border-radius: 16px;
        padding: 14px 16px;
        box-shadow: 0 12px 24px rgba(15, 23, 42, 0.06);
      }
      @media (min-width: 992px) {
        .w-lg-auto {
          width: auto !important;
        }
      }
      .page-title {
        font-weight: 700;
        color: #0f172a;
      }
      .muted-lead {
        color: #64748b;
      }
    </style>
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

function parseGamesInput(input) {
  const lines = input
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  if (!lines.length) {
    return { error: "Informe ao menos um jogo." };
  }

  const games = [];
  for (let index = 0; index < lines.length; index += 1) {
    const { numbers, error } = parseNumbers(lines[index]);
    if (error) {
      return { error: `Linha ${index + 1}: ${error}` };
    }
    games.push(numbers);
  }

  return { games };
}

function insertGames(bolaoId, games, onComplete) {
  const createdAt = new Date().toISOString();
  db.serialize(() => {
    db.run("BEGIN TRANSACTION");
    const insertNext = (index) => {
      if (index >= games.length) {
        return db.run("COMMIT", onComplete);
      }
      db.run(
        "INSERT INTO games (bolao_id, numbers, created_at) VALUES (?, ?, ?)",
        [bolaoId, JSON.stringify(games[index]), createdAt],
        (err) => {
          if (err) {
            return db.run("ROLLBACK", () => onComplete(err));
          }
          return insertNext(index + 1);
        }
      );
    };
    insertNext(0);
  });
}

function parseResultNumbers(input) {
  const { numbers, error } = parseNumbers(input);
  if (error) {
    return { error };
  }
  if (numbers.length !== 6) {
    return { error: "Informe exatamente 6 dezenas." };
  }
  return { numbers };
}

function parseDrawNumber(input) {
  const drawNumber = Number(input);
  if (!Number.isInteger(drawNumber) || drawNumber < 1 || drawNumber > 9999) {
    return { error: "Número do concurso inválido." };
  }
  return { drawNumber };
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function buildResultsEmailHtml({ bolao, draw, gamesStats, maxHits }) {
  const bolaoTitle = getBolaoDisplayName(bolao);
  const bolaoSubtitle = bolaoTitle === `Bolão ${bolao.id}` ? "" : bolao.id;
  const drawNumbers = new Set(draw.numbers);
  const achievement = getHitAchievement(maxHits);
  const sortedGames = sortGameStats(gamesStats, true);
  const gamesHtml = sortedGames.length
    ? sortedGames
        .map((game) => {
          const hits = game.numbers.filter((num) => drawNumbers.has(num));
          const hitLabel =
            hits.length >= 6
              ? "🎉 Premiado!"
              : hits.length >= 4
              ? "Boa!"
              : "Confira";
          const numberBadges = game.numbers
            .map((num) => {
              const active = drawNumbers.has(num);
              const style = active
                ? "background:#16a34a;color:#fff;"
                : "background:#f3f4f6;color:#111827;";
              return `<span style="display:inline-block;margin:2px 4px;padding:6px 10px;border-radius:999px;font-size:12px;${style}">${escapeHtml(
                num
              )}</span>`;
            })
            .join("");
          const isHighlight = achievement && game.hitCount === maxHits;
          const rowStyle = isHighlight
            ? `${achievement.highlight}border-radius:12px;padding:12px;`
            : "padding:12px 0;border-bottom:1px solid #e5e7eb;";
          const rowEmphasis = isHighlight ? achievement.emphasis : "";
          return `
            <tr>
              <td style="${rowStyle}">
                <div style="margin-bottom:6px;">${numberBadges}</div>
                <strong style="color:#111827;${rowEmphasis}">${
                  hits.length
                } acertos</strong>
                <span style="margin-left:8px;color:#6b7280;">${hitLabel}</span>
              </td>
            </tr>
          `;
        })
        .join("")
    : `
        <tr>
          <td style="padding:12px 0;border-bottom:1px solid #e5e7eb;color:#6b7280;">
            Nenhum jogo cadastrado para este bolão.
          </td>
        </tr>
      `;

  return `
    <div style="font-family:Arial,sans-serif;background:#f8fafc;padding:24px;">
      <div style="max-width:620px;margin:0 auto;background:#ffffff;border-radius:16px;padding:24px;border:1px solid #e5e7eb;">
        <h1 style="margin-top:0;font-size:22px;color:#111827;">Resultados do seu bolão</h1>
        <p style="color:#4b5563;font-size:14px;">
          O resultado do concurso <strong>${escapeHtml(
            draw.number
          )}</strong> já está disponível.
        </p>
        ${
          achievement
            ? `<div style="margin:16px 0;padding:14px 16px;border-radius:12px;${achievement.highlight}">
                <strong style="color:#111827;${achievement.emphasis}">${achievement.emoji} ${achievement.title}</strong>
                <div style="color:#4b5563;font-size:13px;margin-top:4px;">Seu melhor jogo teve ${maxHits} acertos.</div>
              </div>`
            : ""
        }
        <div style="background:#eff6ff;border-radius:12px;padding:16px;margin:16px 0;">
          <div style="font-size:14px;color:#1e3a8a;margin-bottom:6px;">Dezenas sorteadas</div>
          <div>
            ${draw.numbers
              .map(
                (num) =>
                  `<span style="display:inline-block;margin:2px 4px;padding:6px 10px;border-radius:999px;background:#2563eb;color:#fff;font-size:12px;">${escapeHtml(
                    num
                  )}</span>`
              )
              .join("")}
          </div>
          <div style="margin-top:8px;font-size:12px;color:#1e3a8a;">
            Apuração em ${escapeHtml(draw.drawDate)}
          </div>
        </div>
        <h2 style="font-size:16px;color:#111827;margin-bottom:8px;">${escapeHtml(
          bolaoTitle
        )}</h2>
        ${
          bolaoSubtitle
            ? `<div style="font-size:12px;color:#6b7280;margin-bottom:8px;">ID ${escapeHtml(
                bolaoSubtitle
              )}</div>`
            : ""
        }
        <table style="width:100%;border-collapse:collapse;">
          <tbody>
            ${gamesHtml}
          </tbody>
        </table>
        <p style="font-size:12px;color:#6b7280;margin-top:16px;">
          Você está recebendo este email porque confirmou o acompanhamento deste bolão.
        </p>
      </div>
    </div>
  `;
}

function buildResultsEmailText({ bolao, draw, gamesStats, maxHits }) {
  const bolaoTitle = getBolaoDisplayName(bolao);
  const bolaoSubtitle = bolaoTitle === `Bolão ${bolao.id}` ? "" : bolao.id;
  const drawNumbers = draw.numbers.join(" ");
  const achievement = getHitAchievement(maxHits);
  const sortedGames = sortGameStats(gamesStats, true);
  const gamesText = sortedGames.length
    ? sortedGames
        .map((game) => {
          const hits = game.numbers.filter((num) => draw.numbers.includes(num));
          const highlightPrefix =
            achievement && game.hitCount === maxHits ? "⭐ " : "";
          return `${highlightPrefix}- ${game.numbers.join(" ")} (${
            hits.length
          } acertos)`;
        })
        .join("\n")
    : "- Nenhum jogo cadastrado.";
  const achievementText = achievement
    ? `\n${achievement.emoji} ${achievement.title} Seu melhor jogo teve ${maxHits} acertos.\n`
    : "\n";
  return `Resultados do seu bolão ${bolaoTitle}${
    bolaoSubtitle ? ` (ID ${bolaoSubtitle})` : ""
  }\nConcurso ${draw.number} (${draw.drawDate})\nDezenas: ${drawNumbers}${achievementText}\nJogos:\n${gamesText}`;
}

function buildSubscriptionEmail({ bolao, token }) {
  const confirmationLink = `${SHARE_BASE_URL}/b/${encodeURIComponent(
    bolao.id
  )}/confirm?token=${encodeURIComponent(token)}`;
  const bolaoTitle = getBolaoDisplayName(bolao);
  const bolaoSubtitle = bolaoTitle === `Bolão ${bolao.id}` ? "" : bolao.id;
  const html = `
    <div style="font-family:Arial,sans-serif;background:#f8fafc;padding:24px;">
      <div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:16px;padding:24px;border:1px solid #e5e7eb;">
        <h1 style="margin-top:0;font-size:20px;color:#111827;">Confirme seu email</h1>
        <p style="color:#4b5563;font-size:14px;">
          Clique no botão abaixo para confirmar que você quer acompanhar o ${escapeHtml(
            bolaoTitle
          )}.
        </p>
        ${
          bolaoSubtitle
            ? `<p style="color:#6b7280;font-size:12px;margin-top:-6px;">ID ${escapeHtml(
                bolaoSubtitle
              )}</p>`
            : ""
        }
        <p>
          <a href="${confirmationLink}" style="display:inline-block;background:#2563eb;color:#fff;text-decoration:none;padding:10px 18px;border-radius:8px;font-size:14px;">Confirmar assinatura</a>
        </p>
        <p style="font-size:12px;color:#6b7280;">Ou copie e cole este link no navegador:<br />${escapeHtml(
          confirmationLink
        )}</p>
      </div>
    </div>
  `;
  const text = `Confirme seu email para acompanhar o ${bolaoTitle}${
    bolaoSubtitle ? ` (ID ${bolaoSubtitle})` : ""
  }: ${confirmationLink}`;
  return { html, text };
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

function parseBrazilDate(value) {
  const match = /^(\d{2})\/(\d{2})\/(\d{4})$/.exec(String(value || "").trim());
  if (!match) return null;
  const [, day, month, year] = match.map(Number);
  const date = new Date(year, month - 1, day, 23, 59, 59, 999);
  return Number.isNaN(date.getTime()) ? null : date;
}

function fetchLatestDrawSummary() {
  return fetch(API_URL)
    .then((res) => res.json())
    .then((data) => {
      if (!data || !data.numero || !data.numeroConcursoProximo) {
        throw new Error("Resposta inválida da API");
      }
      return {
        latestNumber: data.numero,
        latestDrawDate: data.dataApuracao,
        nextNumber: data.numeroConcursoProximo,
        nextDrawDate: data.dataProximoConcurso,
      };
    });
}

function storeDraw(draw) {
  const now = new Date().toISOString();
  return dbRun(
    `INSERT INTO draws (number, numbers, draw_date, updated_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(number) DO UPDATE SET
       numbers = excluded.numbers,
       draw_date = excluded.draw_date,
       updated_at = excluded.updated_at`,
    [draw.number, JSON.stringify(draw.numbers), draw.drawDate, now]
  );
}

async function hasPendingBoloes() {
  const row = await dbGet(
    `SELECT 1
     FROM boloes
     LEFT JOIN draws ON boloes.draw_number = draws.number
     WHERE draws.number IS NULL
     LIMIT 1`
  );
  return Boolean(row);
}

function startPolling() {
  const poll = async () => {
    try {
      const pending = await hasPendingBoloes();
      if (!pending) {
        return;
      }
      const draw = await fetchLatestDraw();
      await storeDraw(draw);
      await notifySubscribersForDraw(draw);
    } catch (err) {
      console.error("Falha ao buscar concurso:", err);
    }
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

async function notifySubscribersForDraw(draw) {
  try {
    const boloes = await dbAll(
      "SELECT id, name, draw_number FROM boloes WHERE draw_number = ?",
      [draw.number]
    );
    if (!boloes.length) return;

    for (const bolao of boloes) {
      const subscribers = await dbAll(
        `SELECT id, email, last_notified_draw
         FROM bolao_subscribers
         WHERE bolao_id = ?
           AND status = 'verified'
           AND (last_notified_draw IS NULL OR last_notified_draw < ?)`,
        [bolao.id, draw.number]
      );
      if (!subscribers.length) continue;

      const games = await dbAll(
        "SELECT id, numbers FROM games WHERE bolao_id = ? ORDER BY id DESC",
        [bolao.id]
      );
      const drawNumbersSet = new Set(draw.numbers);
      const gamesStats = getGameStats(games, drawNumbersSet);
      const maxHits = getMaxHits(gamesStats);
      const emailHtml = buildResultsEmailHtml({
        bolao,
        draw,
        gamesStats,
        maxHits,
      });
      const emailText = buildResultsEmailText({
        bolao,
        draw,
        gamesStats,
        maxHits,
      });

      for (const subscriber of subscribers) {
        try {
          const bolaoTitle = getBolaoDisplayName(bolao);
          await mailTransport.sendMail({
            from: `"${bolaoTitle}" <bolao-${bolao.id}@${FROM_DOMAIN}>`,
            to: subscriber.email,
            subject: `${bolaoTitle} ${maxHits} acertos`,
            text: emailText,
            html: emailHtml,
          });
          logAction("results_sent", {
            bolaoId: bolao.id,
            email: subscriber.email,
            drawNumber: draw.number,
          });
          await dbRun(
            "UPDATE bolao_subscribers SET last_notified_draw = ? WHERE id = ?",
            [draw.number, subscriber.id]
          );
        } catch (err) {
          console.error(
            `Falha ao enviar resultado para ${subscriber.email}:`,
            err
          );
        }
      }
    }
  } catch (err) {
    console.error("Falha ao notificar assinantes:", err);
  }
}

app.get("/", async (req, res) => {
  let nextDrawNumber = "";
  let nextDrawLabel = "";
  try {
    const summary = await fetchLatestDrawSummary();
    nextDrawNumber = summary.nextNumber;
    nextDrawLabel = summary.nextDrawDate
      ? `Próximo concurso em ${summary.nextDrawDate}`
      : "";
  } catch (err) {
    console.error("Falha ao carregar próximo concurso:", err);
  }
  const body = `
    <div class="row">
      <div class="col-lg-8">
        <div class="card shadow-sm">
          <div class="card-body">
            <h1 class="h4 page-title">Criar novo bolão</h1>
            <p class="muted-lead">Informe o número do concurso e cadastre seus jogos.</p>
            <form method="post" action="/bolao">
              <div class="mb-3">
                <label class="form-label">Nome do bolão</label>
                <input class="form-control" name="name" maxlength="80" placeholder="Ex: Família Silva" />
                <div class="form-text">Opcional. Ajuda a identificar o bolão nos emails.</div>
              </div>
              <div class="mb-3">
                <label class="form-label">Número do concurso</label>
                <input class="form-control" name="drawNumber" type="number" min="1" max="9999" step="1" inputmode="numeric" value="${escapeHtml(
                  nextDrawNumber
                )}" required />
                ${
                  nextDrawLabel
                    ? `<div class="form-text">${escapeHtml(nextDrawLabel)}</div>`
                    : ""
                }
              </div>
              <button class="btn btn-primary w-100">Criar bolão</button>
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

app.post("/bolao", async (req, res) => {
  const { drawNumber, error } = parseDrawNumber(req.body.drawNumber);
  if (error) {
    return res
      .status(400)
      .send(renderLayout("Erro", escapeHtml(error)));
  }
  const { name, error: nameError } = parseBolaoName(req.body.name);
  if (nameError) {
    return res
      .status(400)
      .send(renderLayout("Erro", escapeHtml(nameError)));
  }
  try {
    const summary = await fetchLatestDrawSummary();
    const now = new Date();
    const nextDrawDate = parseBrazilDate(summary.nextDrawDate);
    if (drawNumber <= summary.latestNumber) {
      return res
        .status(400)
        .send(
          renderLayout(
            "Erro",
            "Este concurso já foi sorteado. Escolha um concurso futuro."
          )
        );
    }
    if (
      drawNumber === summary.nextNumber &&
      nextDrawDate &&
      now > nextDrawDate
    ) {
      return res
        .status(400)
        .send(
          renderLayout(
            "Erro",
            "O próximo concurso já foi sorteado. Aguarde o próximo número."
          )
        );
    }
  } catch (err) {
    console.error("Falha ao validar concurso:", err);
  }
  const id = generateBolaoId();
  const editToken = crypto.randomBytes(16).toString("hex");
  const createdAt = new Date().toISOString();
  db.run(
    "INSERT INTO boloes (id, name, draw_number, edit_token, created_at) VALUES (?, ?, ?, ?, ?)",
    [id, name, drawNumber, editToken, createdAt],
    (err) => {
      if (err) {
        return res
          .status(500)
          .send(renderLayout("Erro", "Não foi possível criar o bolão."));
      }
      logAction("bolao_created", { id, name, drawNumber });
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
    "SELECT id, name, draw_number, edit_token FROM boloes WHERE id = ?",
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
          let subscribers = [];
          if (authorized) {
            try {
              subscribers = await dbAll(
                `SELECT email, status, created_at, verified_at
                 FROM bolao_subscribers
                 WHERE bolao_id = ?
                 ORDER BY created_at DESC`,
                [id]
              );
            } catch (err) {
              console.error("Falha ao carregar assinantes:", err);
              return res
                .status(500)
                .send(renderLayout("Erro", "Falha ao carregar assinantes."));
            }
          }
          const draw = await getDraw(bolao.draw_number);
          const drawNumbers = draw ? new Set(draw.numbers) : null;
          const resultBadge = draw
            ? `<span class="badge bg-success">Concurso ${draw.number} (${draw.drawDate})</span>`
            : `<span class="badge bg-warning text-dark">Aguardando concurso ${bolao.draw_number}</span>`;

          const gameStats = getGameStats(games, drawNumbers);
          const sortedGames = sortGameStats(gameStats, Boolean(drawNumbers));
          const gamesHtml = sortedGames.length
            ? sortedGames
                .map((game) => {
                  const hits = drawNumbers
                    ? game.numbers.filter((num) => drawNumbers.has(num))
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

                  const list = game.numbers
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

          const bolaoTitle = getBolaoDisplayName(bolao);
          const bolaoSubtitle =
            bolaoTitle === `Bolão ${bolao.id}` ? "" : bolao.id;
          const adminLink = `${SHARE_BASE_URL}/b/${encodeURIComponent(
            id
          )}?token=${encodeURIComponent(bolao.edit_token)}`;
          const shareLink = `${SHARE_BASE_URL}/b/${encodeURIComponent(id)}`;
          const ogTitle = bolaoTitle;
          const ogDescription = draw
            ? `${bolaoTitle} • Concurso ${draw.number} (${draw.drawDate})`
            : `${bolaoTitle} • Concurso ${bolao.draw_number}`;
          const ogImage = `${SHARE_BASE_URL}/bolao.png`;
          const ogTags = `
            <meta property="og:type" content="website" />
            <meta property="og:title" content="${escapeHtml(ogTitle)}" />
            <meta property="og:description" content="${escapeHtml(
              ogDescription
            )}" />
            <meta property="og:url" content="${escapeHtml(shareLink)}" />
            <meta property="og:image" content="${escapeHtml(ogImage)}" />
            <meta property="og:image:alt" content="Bolão Mega-Sena" />
          `;
          const addGameCard = authorized
            ? `
                <div class="card shadow-sm mb-4">
                  <div class="card-body">
                    <h2 class="h6">Adicionar jogos</h2>
                    <form method="post" action="/b/${id}/games">
                      <div class="mb-3">
                        <label class="form-label">Jogos (1 por linha)</label>
                        <textarea class="form-control" name="numbers" rows="4" placeholder="01 05 12 23 34 45&#10;02 08 14 29 37 50" inputmode="numeric" required></textarea>
                        <div class="form-text">Informe de 6 a 15 dezenas por linha, separadas por espaço, vírgula ou ponto-e-vírgula.</div>
                      </div>
                      <button class="btn btn-primary w-100">Salvar jogos</button>
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
          const editNameCard = authorized
            ? `
                <div class="card shadow-sm mb-4">
                  <div class="card-body">
                    <h2 class="h6">Editar nome do bolão</h2>
                    <form method="post" action="/b/${id}/update">
                      <div class="mb-3">
                        <label class="form-label">Nome do bolão</label>
                        <input class="form-control" name="name" maxlength="80" value="${escapeHtml(
                          bolao.name || ""
                        )}" />
                        <div class="form-text">Opcional. Deixe em branco para remover o nome.</div>
                      </div>
                      <button class="btn btn-outline-primary w-100">Salvar nome</button>
                    </form>
                  </div>
                </div>
              `
            : "";
          const subscribeNotice =
            req.query.subscribe === "sent"
              ? `<div class="alert alert-success">Enviamos um email com o link de confirmação. Verifique também a pasta de SPAM caso não encontre.</div>`
              : req.query.confirm === "ok"
              ? `<div class="alert alert-success">Email confirmado! Você receberá os resultados deste bolão.</div>`
              : req.query.confirm === "invalid"
              ? `<div class="alert alert-danger">Link de confirmação inválido ou expirado.</div>`
              : "";

          const subscribeCard = `
            <div class="card shadow-sm mb-4">
              <div class="card-body">
                <h2 class="h6">Receber resultados por email</h2>
                <p class="text-muted small mb-3">Confirme seu email para acompanhar este bolão.</p>
                <form method="post" action="/b/${id}/subscribe">
                  <div class="mb-3">
                    <label class="form-label">Seu email</label>
                    <input class="form-control" name="email" type="email" autocomplete="email" required />
                  </div>
                  <button class="btn btn-outline-primary w-100">Assinar</button>
                </form>
              </div>
            </div>
          `;
          const subscribersCard = authorized
            ? `
                <div class="card shadow-sm mb-4">
                  <div class="card-body">
                    <h2 class="h6">Assinantes</h2>
                    <ul class="list-group list-group-flush">
                      ${
                        subscribers.length
                          ? subscribers
                              .map((subscriber) => {
                                const statusLabel =
                                  subscriber.status === "verified"
                                    ? "Confirmado"
                                    : "Pendente";
                                const statusClass =
                                  subscriber.status === "verified"
                                    ? "bg-success"
                                    : "bg-warning text-dark";
                                const createdAtLabel = new Date(
                                  subscriber.created_at
                                ).toLocaleString("pt-BR");
                                const verifiedAtLabel = subscriber.verified_at
                                  ? new Date(
                                      subscriber.verified_at
                                    ).toLocaleString("pt-BR")
                                  : null;
                                return `<li class="list-group-item d-flex justify-content-between align-items-start flex-wrap gap-2">
                                  <div>
                                    <div class="fw-semibold">${escapeHtml(
                                      subscriber.email
                                    )}</div>
                                    <div class="text-muted small">Inscrito em ${escapeHtml(
                                      createdAtLabel
                                    )}</div>
                                    ${
                                      verifiedAtLabel
                                        ? `<div class="text-muted small">Confirmado em ${escapeHtml(
                                            verifiedAtLabel
                                          )}</div>`
                                        : ""
                                    }
                                  </div>
                                  <span class="badge ${statusClass}">${escapeHtml(
                                  statusLabel
                                )}</span>
                                </li>`;
                              })
                              .join("")
                          : `<li class="list-group-item text-muted">Nenhum assinante ainda.</li>`
                      }
                    </ul>
                  </div>
                </div>
              `
            : "";

          const body = `
            <div class="d-flex flex-column flex-lg-row justify-content-between align-items-start align-items-lg-center gap-3 mb-4">
              <div>
                <h1 class="h4 page-title">${escapeHtml(bolaoTitle)}</h1>
                ${
                  bolaoSubtitle
                    ? `<div class="text-muted small mb-2">ID ${escapeHtml(
                        bolaoSubtitle
                      )}</div>`
                    : ""
                }
                ${resultBadge}
              </div>
              <div class="share-panel w-100 w-lg-auto">
                <small class="text-muted">Link para compartilhar</small>
                <a class="link-box d-block mt-2" href="${escapeHtml(
                  shareLink
                )}">${escapeHtml(shareLink)}</a>
                ${
                  authorized
                    ? `<div class="mt-3"><small class="text-muted">Link do administrador</small><a class="link-box d-block mt-2" href="${escapeHtml(
                        adminLink
                      )}">${escapeHtml(adminLink)}</a></div>`
                    : ""
                }
              </div>
            </div>
            ${subscribeNotice}
            <div class="row">
              <div class="col-lg-4">
                ${addGameCard}
                ${editNameCard}
                ${subscribeCard}
                ${subscribersCard}
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
          res.send(renderLayout(bolaoTitle, body, ogTags));
        }
      );
    }
  );
});

app.post("/b/:id/subscribe", async (req, res) => {
  const { id } = req.params;
  if (!isValidBolaoId(id)) {
    return res
      .status(404)
      .send(renderLayout("Erro", "Bolão não encontrado."));
  }
  const email = String(req.body.email || "").trim().toLowerCase();
  if (!isValidEmail(email)) {
    return res
      .status(400)
      .send(renderLayout("Erro", "Email inválido."));
  }
  try {
    const bolao = await dbGet("SELECT id, name FROM boloes WHERE id = ?", [id]);
    if (!bolao) {
      return res
        .status(404)
        .send(renderLayout("Erro", "Bolão não encontrado."));
    }
    const token = crypto.randomBytes(16).toString("hex");
    const createdAt = new Date().toISOString();
    await dbRun(
      `INSERT INTO bolao_subscribers (bolao_id, email, status, verification_token, created_at)
       VALUES (?, ?, 'pending', ?, ?)
       ON CONFLICT(bolao_id, email) DO UPDATE SET
         status = 'pending',
         verification_token = excluded.verification_token,
         created_at = excluded.created_at,
         verified_at = NULL,
         last_notified_draw = NULL`,
      [id, email, token, createdAt]
    );
    const { html, text } = buildSubscriptionEmail({
      bolao,
      token,
    });
    const bolaoTitle = getBolaoDisplayName(bolao);
    await mailTransport.sendMail({
      from: `"${bolaoTitle}" <bolao-${id}@${FROM_DOMAIN}>`,
      to: email,
      subject: `Confirme seu email para acompanhar o ${bolaoTitle}`,
      text,
      html,
    });
    logAction("subscription_requested", { bolaoId: id, email });
    res.redirect(`/b/${id}?subscribe=sent`);
  } catch (err) {
    console.error("Falha ao cadastrar assinatura:", err);
    res
      .status(500)
      .send(renderLayout("Erro", "Não foi possível enviar o email."));
  }
});

app.get("/b/:id/confirm", async (req, res) => {
  const { id } = req.params;
  const token = String(req.query.token || "").trim();
  if (!isValidBolaoId(id)) {
    return res
      .status(404)
      .send(renderLayout("Erro", "Bolão não encontrado."));
  }
  if (!token) {
    return res.redirect(`/b/${id}?confirm=invalid`);
  }
  try {
    const subscriber = await dbGet(
      "SELECT id FROM bolao_subscribers WHERE bolao_id = ? AND verification_token = ?",
      [id, token]
    );
    if (!subscriber) {
      return res.redirect(`/b/${id}?confirm=invalid`);
    }
    await dbRun(
      `UPDATE bolao_subscribers
       SET status = 'verified',
           verification_token = NULL,
           verified_at = ?
       WHERE id = ?`,
      [new Date().toISOString(), subscriber.id]
    );
    logAction("subscription_confirmed", { bolaoId: id, subscriberId: subscriber.id });
    res.redirect(`/b/${id}?confirm=ok`);
  } catch (err) {
    console.error("Falha ao confirmar assinatura:", err);
    res.redirect(`/b/${id}?confirm=invalid`);
  }
});

app.post("/b/:id/update", (req, res) => {
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
          .send(renderLayout("Erro", "Você não tem permissão para editar este bolão."));
      }
      const { name, error } = parseBolaoName(req.body.name);
      if (error) {
        return res
          .status(400)
          .send(renderLayout("Erro", escapeHtml(error)));
      }
      db.run(
        "UPDATE boloes SET name = ? WHERE id = ?",
        [name, id],
        (errUpdate) => {
          if (errUpdate) {
            return res
              .status(500)
              .send(renderLayout("Erro", "Não foi possível atualizar o bolão."));
          }
          logAction("bolao_name_updated", { id, name });
          res.redirect(`/b/${id}?token=${bolao.edit_token}`);
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
      const { games, error } = parseGamesInput(String(req.body.numbers || ""));
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
      insertGames(id, games, (errInsert) => {
        if (errInsert) {
          return res
            .status(500)
            .send(renderLayout("Erro", "Não foi possível salvar os jogos."));
        }
        logAction("games_added", { bolaoId: id, count: games.length });
        res.redirect(`/b/${id}?token=${bolao.edit_token}`);
      });
    }
  );
});

app.get("/admin", requireAdmin, (req, res) => {
  db.all(
    "SELECT number, numbers, draw_date, updated_at FROM draws ORDER BY number DESC",
    (errDraws, draws) => {
      if (errDraws) {
        return res
          .status(500)
          .send(renderLayout("Admin", "Falha ao carregar sorteios."));
      }
      db.all(
        "SELECT id, name, draw_number, created_at FROM boloes ORDER BY created_at DESC",
        async (err, boloes) => {
          if (err) {
            return res
              .status(500)
              .send(renderLayout("Admin", "Falha ao carregar bolões."));
          }
          let suggestedDrawNumber = "";
          let suggestedDrawLabel = "";
          const latestDrawNumber = draws.length ? Number(draws[0].number) : null;
          if (Number.isInteger(latestDrawNumber)) {
            suggestedDrawNumber = latestDrawNumber + 1;
          }
          try {
            const summary = await fetchLatestDrawSummary();
            suggestedDrawNumber = summary.nextNumber;
            suggestedDrawLabel = summary.nextDrawDate
              ? `sorteio em ${summary.nextDrawDate}`
              : "";
          } catch (errSummary) {
            console.error(
              "Falha ao carregar próximo concurso para o admin:",
              errSummary
            );
          }
          let games = [];
          try {
            games = await dbAll("SELECT bolao_id, numbers FROM games");
          } catch (errGames) {
            console.error("Falha ao carregar jogos para o admin:", errGames);
            return res
              .status(500)
              .send(renderLayout("Admin", "Falha ao carregar jogos."));
          }
          const gamesByBolao = games.reduce((acc, game) => {
            if (!acc[game.bolao_id]) {
              acc[game.bolao_id] = [];
            }
            acc[game.bolao_id].push(JSON.parse(game.numbers));
            return acc;
          }, {});
          const drawsByNumber = draws.reduce((acc, draw) => {
            acc[draw.number] = JSON.parse(draw.numbers);
            return acc;
          }, {});
          const list = boloes.length
            ? boloes
                .map((bolao) => {
                  const shareLink = `${SHARE_BASE_URL}/b/${encodeURIComponent(
                    bolao.id
                  )}`;
                  const title = getBolaoDisplayName(bolao);
                  const subtitle =
                    title === `Bolão ${bolao.id}` ? "" : `ID ${bolao.id}`;
                  const bolaoGames = gamesByBolao[bolao.id] || [];
                  const gameCounts = bolaoGames.reduce((acc, numbers) => {
                    const key = numbers.length;
                    acc[key] = (acc[key] || 0) + 1;
                    return acc;
                  }, {});
                  const gameCountLabel = Object.keys(gameCounts).length
                    ? Object.keys(gameCounts)
                        .map(Number)
                        .sort((a, b) => b - a)
                        .map((size) => `${gameCounts[size]}x ${size}`)
                        .join(" • ")
                    : "Nenhum jogo cadastrado";
                  const drawNumbers = drawsByNumber[bolao.draw_number];
                  const maxHits = drawNumbers
                    ? bolaoGames.reduce((max, numbers) => {
                        const hitCount = numbers.filter((num) =>
                          drawNumbers.includes(num)
                        ).length;
                        return Math.max(max, hitCount);
                      }, 0)
                    : null;
                  const achievement = maxHits ? getHitAchievement(maxHits) : null;
                  const maxHitsLabel =
                    drawNumbers && maxHits !== null
                      ? `Maior acerto: ${maxHits}${
                          achievement ? ` (${achievement.label})` : ""
                        }`
                      : "";
                  return `<li class="list-group-item d-flex flex-column flex-md-row justify-content-between align-items-md-center gap-3">
                    <div>
                      <strong>${escapeHtml(title)}</strong><br />
                      ${
                        subtitle
                          ? `<small class="text-muted">${escapeHtml(
                              subtitle
                            )}</small><br />`
                          : ""
                      }
                      <small class="text-muted">Concurso ${escapeHtml(
                        bolao.draw_number
                      )}</small><br />
                      <small class="text-muted">${escapeHtml(
                        gameCountLabel
                      )}</small>
                      ${
                        maxHitsLabel
                          ? `<br /><small class="text-muted">${escapeHtml(
                              maxHitsLabel
                            )}</small>`
                          : ""
                      }
                      <small class="text-muted text-break d-block">
                        Link: <a href="${escapeHtml(shareLink)}">${escapeHtml(
                          shareLink
                        )}</a>
                      </small>
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
          const drawsList = draws.length
            ? draws
                .map((draw) => {
                  const updatedAtLabel = draw.updated_at
                    ? new Date(draw.updated_at).toLocaleString("pt-BR")
                    : "";
                  return `<li class="list-group-item d-flex flex-column flex-md-row justify-content-between align-items-md-center gap-3">
                    <div>
                      <strong>Concurso ${escapeHtml(draw.number)}</strong><br />
                      <small class="text-muted">Apuração ${escapeHtml(
                        draw.draw_date
                      )}</small>
                      ${
                        updatedAtLabel
                          ? `<br /><small class="text-muted">Atualizado em ${escapeHtml(
                              updatedAtLabel
                            )}</small>`
                          : ""
                      }
                    </div>
                    <form method="post" action="/admin/draws/${encodeURIComponent(
                      draw.number
                    )}/delete">
                      <button class="btn btn-sm btn-outline-danger">Excluir</button>
                    </form>
                  </li>`;
                })
                .join("")
            : `<li class="list-group-item text-muted">Nenhum sorteio cadastrado.</li>`;

          const manualNotice =
            req.query.manual === "ok"
              ? `<div class="alert alert-success">Resultado informado com sucesso.</div>`
              : "";
          const drawDeleteNotice =
            req.query.drawDeleted === "ok"
              ? `<div class="alert alert-success">Sorteio excluído com sucesso.</div>`
              : "";
          const body = `
        <div class="d-flex justify-content-between align-items-center mb-3">
          <div>
            <h1 class="h4">Área administrativa</h1>
            <p class="text-muted mb-0">Gerencie todos os bolões cadastrados.</p>
          </div>
        </div>
        ${manualNotice}
        ${drawDeleteNotice}
        <div class="card shadow-sm mb-4">
          <div class="card-body">
            <h2 class="h6">Informar sorteio manualmente</h2>
            <form method="post" action="/admin/draws/manual">
              <div class="mb-3">
                <label class="form-label">Número do concurso</label>
                <input class="form-control" name="drawNumber" type="number" min="1" max="9999" step="1" inputmode="numeric" value="${escapeHtml(
                  suggestedDrawNumber
                )}" required />
                ${
                  suggestedDrawLabel
                    ? `<div class="form-text">${escapeHtml(
                        suggestedDrawLabel
                      )}</div>`
                    : ""
                }
              </div>
              <div class="mb-3">
                <label class="form-label">Dezenas sorteadas</label>
                <input class="form-control" name="numbers" placeholder="Ex: 01 05 12 23 34 45" pattern="^\\s*\\d{1,2}(?:\\s*[ ,;-]\\s*\\d{1,2}){5}\\s*$" inputmode="numeric" required />
                <div class="form-text">Informe exatamente 6 dezenas.</div>
              </div>
              <button class="btn btn-outline-primary">Salvar resultado</button>
            </form>
          </div>
        </div>
        <div class="card shadow-sm mb-4">
          <div class="card-body">
            <h2 class="h6">Sorteios realizados</h2>
            <ul class="list-group list-group-flush">
              ${drawsList}
            </ul>
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
    }
  );
});

app.post("/admin/draws/manual", requireAdmin, async (req, res) => {
  const { drawNumber, error } = parseDrawNumber(req.body.drawNumber);
  if (error) {
    return res
      .status(400)
      .send(renderLayout("Admin", escapeHtml(error)));
  }
  const { numbers, error: numbersError } = parseResultNumbers(
    String(req.body.numbers || "")
  );
  if (numbersError) {
    return res
      .status(400)
      .send(renderLayout("Admin", escapeHtml(numbersError)));
  }
  const drawDate = new Date().toLocaleDateString("pt-BR");
  try {
    await storeDraw({
      number: drawNumber,
      numbers,
      drawDate,
    });
    await notifySubscribersForDraw({
      number: drawNumber,
      numbers,
      drawDate,
    });
    logAction("draw_manual_added", { drawNumber, numbers });
    res.redirect("/admin?manual=ok");
  } catch (err) {
    console.error("Falha ao salvar sorteio manual:", err);
    res
      .status(500)
      .send(renderLayout("Admin", "Falha ao salvar o sorteio."));
  }
});

app.post("/admin/draws/:number/delete", requireAdmin, (req, res) => {
  const { drawNumber, error } = parseDrawNumber(req.params.number);
  if (error) {
    return res.status(400).send(renderLayout("Admin", escapeHtml(error)));
  }
  db.serialize(() => {
    db.run(
      "UPDATE bolao_subscribers SET last_notified_draw = NULL WHERE last_notified_draw = ?",
      [drawNumber],
      (errReset) => {
        if (errReset) {
          return res
            .status(500)
            .send(renderLayout("Admin", "Falha ao atualizar assinantes."));
        }
        db.run("DELETE FROM draws WHERE number = ?", [drawNumber], (errDelete) => {
          if (errDelete) {
            return res
              .status(500)
              .send(renderLayout("Admin", "Falha ao excluir sorteio."));
          }
          logAction("draw_deleted_by_admin", { drawNumber });
          res.redirect("/admin?drawDeleted=ok");
        });
      }
    );
  });
});

app.post("/admin/email/test", requireAdmin, async (req, res) => {
  const to = String(req.body.to || req.query.to || "").trim().toLowerCase();
  if (!isValidEmail(to)) {
    return res.status(400).json({ ok: false, error: "Email inválido." });
  }
  try {
    await mailTransport.sendMail({
      from: `"Bolão Mega-Sena" <no-reply@${FROM_DOMAIN}>`,
      to,
      subject: "Teste de email - Bolão Mega-Sena",
      text: "Este é um email de teste enviado pelo sistema.",
    });
    return res.json({ ok: true });
  } catch (err) {
    console.error("Falha ao enviar email de teste:", err);
    return res.status(500).json({
      ok: false,
      error: "Falha ao enviar email de teste.",
    });
  }
});

app.get("/admin/boloes/:id", requireAdmin, (req, res) => {
  const { id } = req.params;
  if (!isValidBolaoId(id)) {
    return res
      .status(404)
      .send(renderLayout("Admin", "Bolão não encontrado."));
  }
  db.get(
    "SELECT id, name, draw_number, edit_token, created_at FROM boloes WHERE id = ?",
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
          db.all(
            `SELECT email, status, created_at, verified_at
             FROM bolao_subscribers
             WHERE bolao_id = ?
             ORDER BY created_at DESC`,
            [id],
            (errSubscribers, subscribers) => {
              if (errSubscribers) {
                return res
                  .status(500)
                  .send(renderLayout("Admin", "Falha ao carregar assinantes."));
              }
              const shareLink = `${SHARE_BASE_URL}/b/${encodeURIComponent(
                bolao.id
              )}`;
              const adminLink = `${SHARE_BASE_URL}/b/${encodeURIComponent(
                bolao.id
              )}?token=${encodeURIComponent(bolao.edit_token)}`;
              const bolaoTitle = getBolaoDisplayName(bolao);
              const bolaoSubtitle =
                bolaoTitle === `Bolão ${bolao.id}` ? "" : `ID ${bolao.id}`;
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
              const subscribersHtml = subscribers.length
                ? subscribers
                    .map((subscriber) => {
                      const statusLabel =
                        subscriber.status === "verified"
                          ? "Confirmado"
                          : "Pendente";
                      const statusClass =
                        subscriber.status === "verified"
                          ? "bg-success"
                          : "bg-warning text-dark";
                      const createdAtLabel = new Date(
                        subscriber.created_at
                      ).toLocaleString("pt-BR");
                      const verifiedAtLabel = subscriber.verified_at
                        ? new Date(subscriber.verified_at).toLocaleString(
                            "pt-BR"
                          )
                        : null;
                      return `<li class="list-group-item d-flex justify-content-between align-items-start flex-wrap gap-2">
                        <div>
                          <div class="fw-semibold">${escapeHtml(
                            subscriber.email
                          )}</div>
                          <div class="text-muted small">Inscrito em ${escapeHtml(
                            createdAtLabel
                          )}</div>
                          ${
                            verifiedAtLabel
                              ? `<div class="text-muted small">Confirmado em ${escapeHtml(
                                  verifiedAtLabel
                                )}</div>`
                              : ""
                          }
                        </div>
                        <span class="badge ${statusClass}">${escapeHtml(
                        statusLabel
                      )}</span>
                      </li>`;
                    })
                    .join("")
                : `<li class="list-group-item text-muted">Nenhum assinante ainda.</li>`;

              const body = `
            <div class="d-flex justify-content-between align-items-center mb-3">
              <div>
                <h1 class="h4">Administração do ${escapeHtml(
                  bolaoTitle
                )}</h1>
                ${
                  bolaoSubtitle
                    ? `<small class="text-muted d-block">${escapeHtml(
                        bolaoSubtitle
                      )}</small>`
                    : ""
                }
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
                    <h2 class="h6">Editar bolão</h2>
                    <form method="post" action="/admin/boloes/${bolao.id}/update">
                      <div class="mb-3">
                        <label class="form-label">Nome do bolão</label>
                        <input class="form-control" name="name" maxlength="80" value="${escapeHtml(
                          bolao.name || ""
                        )}" />
                        <div class="form-text">Opcional. Deixe em branco para remover o nome.</div>
                      </div>
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
                    <h2 class="h6">Adicionar jogos</h2>
                    <form method="post" action="/admin/boloes/${bolao.id}/games">
                      <div class="mb-3">
                        <label class="form-label">Jogos (1 por linha)</label>
                        <textarea class="form-control" name="numbers" rows="4" placeholder="01 05 12 23 34 45&#10;02 08 14 29 37 50" inputmode="numeric" required></textarea>
                        <div class="form-text">Informe de 6 a 15 dezenas por linha, separadas por espaço, vírgula ou ponto-e-vírgula.</div>
                      </div>
                      <button class="btn btn-outline-primary w-100">Salvar jogos</button>
                    </form>
                  </div>
                </div>
                <div class="card border-0 bg-white shadow-sm">
                  <div class="card-body">
                    <h2 class="h6">Links</h2>
                    <p class="small text-muted mb-2">Compartilhamento:</p>
                    <a class="small link-box d-block" href="${escapeHtml(
                      shareLink
                    )}">${escapeHtml(shareLink)}</a>
                    <p class="small text-muted mt-3 mb-2">Administrador:</p>
                    <a class="small link-box d-block" href="${escapeHtml(
                      adminLink
                    )}">${escapeHtml(adminLink)}</a>
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
                <div class="card shadow-sm mb-4">
                  <div class="card-body">
                    <h2 class="h6">Assinantes</h2>
                    <ul class="list-group list-group-flush">
                      ${subscribersHtml}
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
  const { name, error: nameError } = parseBolaoName(req.body.name);
  if (nameError) {
    return res
      .status(400)
      .send(renderLayout("Admin", escapeHtml(nameError)));
  }
  db.run(
    "UPDATE boloes SET name = ?, draw_number = ? WHERE id = ?",
    [name, drawNumber, id],
    (err) => {
      if (err) {
        return res
          .status(500)
          .send(renderLayout("Admin", "Falha ao atualizar bolão."));
      }
      logAction("bolao_updated_by_admin", { id, name, drawNumber });
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
  const { games, error } = parseGamesInput(String(req.body.numbers || ""));
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
  insertGames(id, games, (err) => {
    if (err) {
      return res
        .status(500)
        .send(renderLayout("Admin", "Não foi possível salvar os jogos."));
    }
    logAction("games_added_by_admin", { bolaoId: id, count: games.length });
    res.redirect(`/admin/boloes/${id}`);
  });
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
        logAction("bolao_deleted_by_admin", { id });
        res.redirect("/admin");
      });
    });
  });
});

app.use((req, res) => {
  res.status(404).send(renderLayout("404", "Página não encontrada."));
});

initDb();
ensureColumnExists("boloes", "name", "TEXT");
ensureColumnExists("boloes", "edit_token", "TEXT", backfillEditTokens);
startPolling();

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
