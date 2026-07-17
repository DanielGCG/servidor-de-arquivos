const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const config = require('./config');
const auth = require('./auth');
const services = require('./services');

const router = express.Router();

const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    let folder = req.query.folder || '';
    folder = folder.replace(/[^a-zA-Z0-9-_ /.]/g, '').replace(/\.\./g, '');
    const dest = path.join(config.state.uploadFolder, folder);
    if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
    cb(null, dest);
  },
  filename: function(req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 1024 * 1024 * 1024 },
  fileFilter: function(req, file, cb) {
    const allowedTypes = [
      'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml',
      'video/mp4', 'video/quicktime', 'video/webm', 'video/x-m4v', 'video/x-matroska', 'video/avi', 'video/mpeg', 'video/x-msvideo',
      'audio/mpeg', 'audio/mp3', 'audio/wav', 'audio/ogg', 'audio/aac',
      'application/octet-stream'
    ];
    
    const isAllowedMime = allowedTypes.includes(file.mimetype);
    const isAllowedExt = /\.(mp4|mov|webm|m4v|mkv|avi|mpg|mpeg|mp3|wav|ogg|aac|jpg|jpeg|png|gif|webp|svg)$/i.test(file.originalname);

    if (isAllowedMime || isAllowedExt) {
      cb(null, true);
    } else {
      console.log(`[UPLOAD] Bloqueado: ${file.originalname}`);
      cb(new Error('Tipo não permitido'));
    }
  }
});

router.post('/upload', auth.apiKeyMiddleware, function(req, res) {
  upload.single('file')(req, res, async function(err) {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado' });

    try {
      const folder = req.query.folder ? req.query.folder.replace(/[^a-zA-Z0-9-_ /.]/g, '').replace(/\.\./g, '') : '';
      const tempFilePath = req.file.path;
      const size = req.file.size;
      const isMediaLarge = req.file.mimetype.startsWith('video/') || /\.(mp4|mov|webm|m4v|mkv|avi|mpg|mpeg)$/i.test(req.file.originalname);
      const limit = isMediaLarge ? 1024 * 1024 * 1024 : 50 * 1024 * 1024;

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
      const fileUrl = `${req.protocol}://${req.get('host')}/files/${relativePath.replace(/\\/g, '/')}?token=${token}`;
      
      res.json({ message: 'Upload bem-sucedido', url: fileUrl, duplicate: fs.existsSync(masterPath) });
    } catch (err) {
      res.status(500).json({ error: 'Erro ao processar upload' });
    }
  });
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
        const fileUrl = `${req.protocol}://${req.get('host')}/files/${relativePath}?token=${token}`;
        
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
