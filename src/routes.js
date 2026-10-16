const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const config = require('./config');
const auth = require('./auth');
const services = require('./services');

const router = express.Router();
const CHUNK_BYTES = 64 * 1024 * 1024;
const MIN_CHUNK_BYTES = 1024 * 1024;

function getPublicBaseUrl(req) {
  return (process.env.PUBLIC_URL || `${req.protocol}://${req.get('host')}`).replace(/\/+$/, '');
}

function sanitizeFolder(folder) {
  return (folder || '').replace(/[^a-zA-Z0-9-_ /.]/g, '').replace(/\.\./g, '');
}

function isAllowedFile(file) {
  const allowedTypes = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml',
    'video/mp4', 'video/quicktime', 'video/webm', 'video/x-m4v', 'video/x-matroska', 'video/avi', 'video/mpeg', 'video/x-msvideo',
    'audio/mpeg', 'audio/mp3', 'audio/wav', 'audio/ogg', 'audio/aac',
    'application/octet-stream'
  ];
  const isAllowedMime = allowedTypes.includes(file.mimetype);
  const isAllowedExt = /\.(mp4|mov|webm|m4v|mkv|avi|mpg|mpeg|mp3|wav|ogg|aac|jpg|jpeg|png|gif|webp|svg)$/i.test(file.originalname);
  return isAllowedMime || isAllowedExt;
}

const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    // Com ticket, a pasta é ditada pelo backend e não pelo cliente
    const folder = sanitizeFolder(req.uploadTicket ? req.uploadTicket.f : req.query.folder);
    const dest = path.join(config.state.uploadFolder, folder);
    if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
    cb(null, dest);
  },
  filename: function(req, file, cb) {
    const name = req.uploadTicket && req.uploadTicket.n ? req.uploadTicket.n : file.originalname;
    cb(null, Date.now() + '-' + name);
  }
});

const chunkStorage = multer.diskStorage({
  destination: function(req, file, cb) {
    const dir = path.join(config.state.storeFolder, '.chunks', req.uploadTicket.j);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: function(req, file, cb) {
    cb(null, `${req.query.index}.part`);
  }
});

function ticketFileFilter(req, file, cb) {
  const prefixes = Array.isArray(req.uploadTicket.t) ? req.uploadTicket.t : [];
  const typeOk = prefixes.length === 0 || prefixes.some(p => (file.mimetype || '').startsWith(p));
  if (isAllowedFile(file) && typeOk) return cb(null, true);
  console.log(`[UPLOAD] Bloqueado (ticket): ${file.originalname} (${file.mimetype})`);
  cb(new Error('Tipo não permitido'));
}

// Upload direto: limite e tipos vêm do ticket assinado
function directUpload(req, res, next) {
  const ticket = req.uploadTicket;
  const handler = multer({
    storage: storage,
    limits: { fileSize: ticket.m || 50 * 1024 * 1024, files: 1 },
    fileFilter: ticketFileFilter
  }).single('file');

  handler(req, res, function(err) {
    if (err) {
      const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
      return res.status(status).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'Arquivo muito grande' : err.message });
    }

    next();
  });
}

function chunkUpload(req, res) {
  const index = Number(req.query.index);
  const total = Number(req.query.total);
  if (!Number.isInteger(index) || !Number.isInteger(total) || total < 1 || index < 0 || index >= total) {
    return res.status(400).json({ error: 'Parte de upload inválida' });
  }
  const expectedSize = Number(req.uploadTicket.s);
  if (total > 10000 || (Number.isFinite(expectedSize) && total > Math.ceil(expectedSize / MIN_CHUNK_BYTES))) {
    return res.status(400).json({ error: 'Quantidade de partes inválida' });
  }

  const handler = multer({
    storage: chunkStorage,
    limits: { fileSize: CHUNK_BYTES, files: 1 },
    fileFilter: ticketFileFilter
  }).single('file');

  handler(req, res, async function(err) {
    if (err) {
      const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
      return res.status(status).json({ error: err.code === 'LIMIT_FILE_SIZE'
        ? 'Não foi possível enviar esta parte. Tente novamente.'
        : err.message });
    }
    if (!req.file) return res.status(400).json({ error: 'Nenhuma parte enviada' });

    const chunkDir = path.dirname(req.file.path);
    const parts = Array.from({ length: total }, (_, partIndex) =>
      path.join(chunkDir, `${partIndex}.part`)
    );
    const received = parts.filter(part => fs.existsSync(part));
    if (received.length !== total) {
      return res.json({ received: true, index, complete: false });
    }

    if (Number.isFinite(expectedSize)) {
      const receivedSize = received.reduce((sum, part) => sum + fs.statSync(part).size, 0);
      if (receivedSize !== expectedSize) {
        return res.status(400).json({ error: 'Tamanho total do upload não confere' });
      }
    }

    const assembledPath = path.join(chunkDir, 'assembled.upload');
    try {
      if (fs.existsSync(assembledPath)) fs.unlinkSync(assembledPath);
      const output = fs.createWriteStream(assembledPath);
      output.on('error', error => console.error('[UPLOAD] Erro ao gravar upload montado:', error));
      for (const part of parts) {
        await new Promise((resolve, reject) => {
          const input = fs.createReadStream(part);
          input.on('error', reject);
          input.on('end', resolve);
          input.pipe(output, { end: false });
        });
      }
      await new Promise((resolve, reject) => {
        output.once('error', reject);
        output.end(resolve);
      });

      if (!auth.consumeTicket(req.uploadTicket)) {
        return res.status(409).json({ error: 'Ticket de upload já utilizado' });
      }
      req.file = {
        path: assembledPath,
        size: fs.statSync(assembledPath).size,
        filename: `${Date.now()}-${req.uploadTicket.n}`
      };
      const folder = sanitizeFolder(req.uploadTicket.f);
      await finalizeUpload(req, res, folder, req.uploadTicket.m || 50 * 1024 * 1024);
      fs.rmSync(chunkDir, { recursive: true, force: true });
    } catch (assemblyError) {
      console.error('[UPLOAD] Erro ao montar partes:', assemblyError);
      if (!res.headersSent) res.status(500).json({ error: 'Erro ao montar upload' });
    }
  });
}

async function finalizeUpload(req, res, folder, limit) {
  if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado' });

  try {
    const tempFilePath = req.file.path;
    const size = req.file.size;

    if (size > limit) {
      if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
      return res.status(400).json({ error: `Arquivo muito grande. Limite: ${limit / (1024 * 1024)}MB` });
    }

    const fileHash = await services.calculateHash(tempFilePath);
    const masterPath = path.join(config.state.storeFolder, fileHash);
    const relativePath = (folder ? folder + '/' : '') + req.file.filename;
    const targetPath = path.join(config.state.uploadFolder, relativePath);

    if (!fs.existsSync(masterPath)) {
      fs.renameSync(tempFilePath, masterPath);
    } else if (fs.existsSync(tempFilePath)) {
      fs.unlinkSync(tempFilePath);
    }

    try {
      if (fs.existsSync(targetPath)) fs.unlinkSync(targetPath);
      fs.linkSync(masterPath, targetPath);
    } catch (linkErr) {
      fs.copyFileSync(masterPath, targetPath);
    }

    config.state.fileHashes[fileHash] = masterPath;
    config.saveHashes();

    const token = auth.generatePermanentToken(relativePath);
    const fileUrl = `${getPublicBaseUrl(req)}/files/${relativePath.replace(/\\/g, '/')}?token=${token}`;

    res.json({ message: 'Upload bem-sucedido', url: fileUrl, duplicate: fs.existsSync(masterPath) });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao processar upload' });
  }
}

router.post('/upload-ticket', auth.apiKeyMiddleware, function(req, res) {
  const { folder, name, type, size } = req.body || {};
  const filename = path.basename(String(name || ''));
  const mime = String(type || 'application/octet-stream');
  if (!filename || !folder) return res.status(400).json({ error: 'folder e name são obrigatórios' });

  const ticket = auth.createUploadTicket({
    folder: sanitizeFolder(folder),
    filename,
    maxBytes: 1024 * 1024 * 1024,
    size,
    mimePrefixes: mime === 'application/octet-stream' ? [] : [`${mime.split('/')[0]}/`, 'application/octet-stream']
  });
  res.json({ uploadUrl: `/upload-direct?ticket=${encodeURIComponent(ticket)}` });
});

// Upload direto do navegador, autenticado por ticket emitido pelo backend (sem expor a API_KEY)
router.post('/upload-direct', auth.uploadTicketMiddleware, function(req, res, next) {
  if (req.query.chunked === '1') return chunkUpload(req, res, next);
  directUpload(req, res, next);
}, function(req, res) {
  const folder = sanitizeFolder(req.uploadTicket.f);
  finalizeUpload(req, res, folder, req.uploadTicket.m || 50 * 1024 * 1024);
});

router.get('/list', auth.apiKeyMiddleware, function(req, res) {
  const getAllFiles = (dirPath, arrayOfFiles) => {
    const files = fs.readdirSync(dirPath);
    arrayOfFiles = arrayOfFiles || [];
    files.forEach(function(file) {
      if (file === '.store') return;
      const fullPath = path.join(dirPath, file);
      if (fs.statSync(fullPath).isDirectory()) {
        arrayOfFiles = getAllFiles(fullPath, arrayOfFiles);
      } else {
        const stats = fs.statSync(fullPath);
        const relativePath = path.relative(config.state.uploadFolder, fullPath).replace(/\\/g, '/');
        const token = auth.generatePermanentToken(relativePath);
        const fileUrl = `${getPublicBaseUrl(req)}/files/${relativePath}?token=${token}`;
        
        arrayOfFiles.push({ name: file, path: relativePath, url: fileUrl, size: stats.size, mtime: stats.mtime, ino: stats.ino });
      }
    });
    return arrayOfFiles;
  };

  try {
    const fileList = getAllFiles(config.state.uploadFolder);
    const grouped = {};
    
    fileList.forEach(file => {
      if (!grouped[file.ino]) grouped[file.ino] = { ino: file.ino, size: file.size, mtime: file.mtime, logicalLinks: [] };
      grouped[file.ino].logicalLinks.push({ name: file.name, path: file.path, url: file.url });
    });

    const result = Object.values(grouped).map(group => {
      group.logicalLinks.sort((a, b) => a.path.localeCompare(b.path));
      group.linkCount = group.logicalLinks.length;
      return group;
    });

    result.sort((a, b) => b.linkCount !== a.linkCount ? b.linkCount - a.linkCount : new Date(b.mtime) - new Date(a.mtime));
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar arquivos' });
  }
});

router.delete('/delete', auth.apiKeyMiddleware, function(req, res) {
  const relPath = req.body.filepath || '';
  if (!relPath) return res.status(400).json({ error: 'filepath obrigatório' });
  const safePath = relPath.split('/').map(p => p.replace(/[^a-zA-Z0-9-_ .]/g, '')).join(path.sep);
  const filePath = path.join(config.state.uploadFolder, safePath);
  
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
    res.json({ message: 'Arquivo removido com sucesso' });
  } else {
    res.status(404).json({ error: 'Arquivo não encontrado' });
  }
});

router.post('/delete-batch', auth.apiKeyMiddleware, function(req, res) {
  const { paths: filePaths } = req.body;
  if (!Array.isArray(filePaths)) return res.status(400).json({ error: 'paths deve ser um array' });

  const results = [];
  for (const relPath of filePaths) {
    try {
      const safePath = relPath.split('/').map(p => p.replace(/[^a-zA-Z0-9-_ .]/g, '')).join(path.sep);
      const filePath = path.join(config.state.uploadFolder, safePath);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        results.push({ success: true, file: relPath });
      } else {
        results.push({ success: false, file: relPath, error: 'Não encontrado' });
      }
    } catch (e) {
      results.push({ success: false, file: relPath, error: e.message });
    }
  }
  res.json({ message: 'Exclusão processada', results });
});

router.post('/sync', auth.apiKeyMiddleware, async function(req, res) {
  try {
    const { validPaths } = req.body;
    if (!Array.isArray(validPaths)) return res.status(400).json({ error: 'validPaths deve ser um array' });
    const validSet = new Set(validPaths.map(p => p.replace(/\\/g, '/').replace(/^\/+/, '')));

    const getAllFiles = (dirPath, arrayOfFiles) => {
      if (!fs.existsSync(dirPath)) return arrayOfFiles || [];
      const files = fs.readdirSync(dirPath);
      arrayOfFiles = arrayOfFiles || [];
      files.forEach(function(file) {
        if (file === '.store') return;
        const fullPath = path.join(dirPath, file);
        if (fs.statSync(fullPath).isDirectory()) arrayOfFiles = getAllFiles(fullPath, arrayOfFiles);
        else arrayOfFiles.push(fullPath);
      });
      return arrayOfFiles;
    };

    const allFiles = getAllFiles(config.state.uploadFolder);
    let removed = 0, kept = 0;

    for (const fullPath of allFiles) {
      const relPath = path.relative(config.state.uploadFolder, fullPath).replace(/\\/g, '/');
      if (!validSet.has(relPath)) {
        try { fs.unlinkSync(fullPath); removed++; } catch (e) {}
      } else kept++;
    }

    const cleanupStats = await services.cleanupStore();
    res.json({ message: 'Sincronização concluída', uploadsRemoved: removed, uploadsKept: kept, storeCleanup: cleanupStats });
  } catch (err) {
    res.status(500).json({ error: 'Erro durante a sincronização' });
  }
});

router.post('/sanitize', auth.apiKeyMiddleware, async function(req, res) {
  try {
    const indexStats = await services.indexExistingFiles();
    const cleanupStats = await services.cleanupStore();
    res.json({ message: 'Sanitização concluída', index: indexStats, cleanup: cleanupStats });
  } catch (err) {
    res.status(500).json({ error: 'Erro durante a sanitização' });
  }
});

router.post('/migrate-root', auth.apiKeyMiddleware, (req, res) => {
  const { newRoot } = req.body;
  if (!newRoot) return res.status(400).json({ error: 'Caminho newRoot é obrigatório.' });

  try {
    services.startMigration(newRoot);
    res.json({ message: 'Migração iniciada com sucesso. Acompanhe o progresso em /migrate-status' });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

router.get('/migrate-status', auth.apiKeyMiddleware, (req, res) => {
  res.json({ ...services.getMigrationState(), currentRoot: config.state.uploadFolder });
});

router.post('/move', auth.apiKeyMiddleware, (req, res) => {
  const { moves } = req.body;
  if (!Array.isArray(moves)) return res.status(400).json({ error: 'moves deve ser um array' });

  const results = [];
  for (const move of moves) {
    const { oldPath, newFolder } = move;
    try {
      const safeOldPath = oldPath.split('/').map(p => p.replace(/[^a-zA-Z0-9-_ .]/g, '')).join(path.sep);
      const safeNewFolder = (newFolder || '').split('/').map(p => p.replace(/[^a-zA-Z0-9-_ .]/g, '')).join(path.sep);
      const fullOldPath = path.join(config.state.uploadFolder, safeOldPath);
      const fileName = path.basename(safeOldPath);
      const fullNewFolder = path.join(config.state.uploadFolder, safeNewFolder);
      const fullNewPath = path.join(fullNewFolder, fileName);

      if (!fs.existsSync(fullOldPath)) {
        results.push({ success: false, file: oldPath, error: 'Não encontrado' });
        continue;
      }

      if (!fs.existsSync(fullNewFolder)) fs.mkdirSync(fullNewFolder, { recursive: true });
      fs.renameSync(fullOldPath, fullNewPath);
      results.push({ success: true, file: oldPath, newPath: path.join(safeNewFolder, fileName).replace(/\\/g, '/') });

    } catch (e) {
      results.push({ success: false, file: oldPath, error: e.message });
    }
  }
  res.json({ message: 'Processamento concluído', results });
});

module.exports = router;
