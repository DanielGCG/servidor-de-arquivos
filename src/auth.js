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

module.exports = {
  generatePermanentToken,
  verifyPermanentToken,
  apiKeyMiddleware
};
