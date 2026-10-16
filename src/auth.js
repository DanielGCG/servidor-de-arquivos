const crypto = require('crypto');

function generatePermanentToken(relativePath) {
  return crypto
    .createHmac('sha256', process.env.API_KEY || 'default_secret')
    .update(relativePath)
    .digest('hex')
    .substring(0, 16);
}

function verifyPermanentToken(relativePath, token) {
  if (!token) return false;
  const expectedToken = generatePermanentToken(relativePath);
  return token === expectedToken;
}

function apiKeyMiddleware(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.query.key;
  
  if (apiKey && apiKey === process.env.API_KEY) {
    return next();
  }

  let relativePath = req.path;
  if (relativePath.startsWith('/files/')) {
    relativePath = relativePath.replace('/files/', '');
  } 
  if (relativePath.startsWith('/')) {
    relativePath = relativePath.substring(1);
  }

  const { token } = req.query;
  if (token && verifyPermanentToken(decodeURIComponent(relativePath), token)) {
    return next();
  }

  console.log(`[AUTH] Negado: ${req.method} ${req.originalUrl}`);
  res.status(401).json({ error: 'Não autorizado' });
}

// ---- Tickets de upload direto ----
// Emitidos pelo backend (Teco) após autenticar/validar o usuário e verificados aqui.
// Formato: base64url(payload JSON) + '.' + HMAC-SHA256(payload)
// Payload: { f: pasta, n: nome do arquivo, m: tamanho máximo (bytes), t: prefixos de mime permitidos, e: expiração (ms epoch), j: nonce }
const usedTicketNonces = new Map(); // nonce -> exp

function signTicketPayload(b64) {
  return crypto
    .createHmac('sha256', (process.env.API_KEY || 'default_secret') + ':upload-ticket')
    .update(b64)
    .digest('base64url');
}

function verifyUploadTicket(ticket) {
  if (typeof ticket !== 'string') return null;
  const [b64, sig] = ticket.split('.');
  if (!b64 || !sig) return null;

  const expected = signTicketPayload(b64);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  let payload;
  try {
    payload = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
  } catch (e) {
    return null;
  }
  if (!payload || typeof payload.e !== 'number' || payload.e < Date.now()) return null;
  return payload;
}

// Marca o ticket como usado (uso único). Retorna false se já foi consumido.
function consumeTicket(payload) {
  const now = Date.now();
  for (const [nonce, exp] of usedTicketNonces) {
    if (exp < now) usedTicketNonces.delete(nonce);
  }
  if (usedTicketNonces.has(payload.j)) return false;
  usedTicketNonces.set(payload.j, payload.e);
  return true;
}

function uploadTicketMiddleware(req, res, next) {
  const payload = verifyUploadTicket(req.query.ticket);
  if (!payload) {
    console.log(`[AUTH] Ticket de upload inválido/expirado: ${req.originalUrl.split('?')[0]}`);
    return res.status(401).json({ error: 'Ticket de upload inválido ou expirado' });
  }
  if (!consumeTicket(payload)) {
    return res.status(401).json({ error: 'Ticket de upload já utilizado' });
  }
  req.uploadTicket = payload;
  next();
}

module.exports = {
  generatePermanentToken,
  verifyPermanentToken,
  apiKeyMiddleware,
  verifyUploadTicket,
  uploadTicketMiddleware
};
