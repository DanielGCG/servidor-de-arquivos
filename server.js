require('dotenv').config();
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const http = require('http');
const crypto = require('crypto');

// Configuração de pastas
const uploadFolder = path.join(__dirname, 'uploads');
const storeFolder = path.join(uploadFolder, '.store');
const tempFolder = path.join(__dirname, 'temp');

if (!fs.existsSync(uploadFolder)) fs.mkdirSync(uploadFolder);
if (!fs.existsSync(storeFolder)) fs.mkdirSync(storeFolder, { recursive: true });
if (!fs.existsSync(tempFolder)) fs.mkdirSync(tempFolder, { recursive: true });

// Arquivo para armazenar os hashes e evitar duplicatas
const hashesFile = path.join(__dirname, 'hashes.json');
let fileHashes = {};

if (fs.existsSync(hashesFile)) {
  try {
    fileHashes = JSON.parse(fs.readFileSync(hashesFile, 'utf8'));
  } catch (e) {
    fileHashes = {};
  }
}

function saveHashes() {
  fs.writeFileSync(hashesFile, JSON.stringify(fileHashes, null, 2));
}

function calculateHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', data => hash.update(data));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', err => reject(err));
  });
}

// Função para sanitizar nomes de arquivos e pastas
function sanitizeName(name, isFolder = false) {
  if (!name) return '';
  
  // Se for pasta, preserva as barras mas limpa o resto
  if (isFolder) {
    return name
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/[^a-zA-Z0-9-_ /.]/g, '_')
      .replace(/\.\./g, '')
      .replace(/\/+/g, '/')
      .trim();
  }

  const ext = path.extname(name);
  const base = path.basename(name, ext);
  
  const sanitizedBase = base
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '') // Remove acentos
    .replace(/[^a-zA-Z0-9-_]/g, '_') // Apenas letras, números, - e _
    .replace(/_{2,}/g, '_') // Remove __ duplicados
    .substring(0, 120); // Limita tamanho do nome

  return sanitizedBase + ext.toLowerCase();
}

// Funções para URLs com Tokens Fixos (Segurança sem expiração)
function generatePermanentToken(relativePath) {
  // Gera um hash único para o arquivo usando a API_KEY como segredo
  // Isso torna a URL fixa, mas impossível de prever sem a chave
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

// Função para indexar arquivos existentes (roda no início)
async function indexExistingFiles() {
  const getAllFiles = (dirPath, arrayOfFiles) => {
    if (!fs.existsSync(dirPath)) return arrayOfFiles || [];
    const files = fs.readdirSync(dirPath);
    arrayOfFiles = arrayOfFiles || [];
    files.forEach(function(file) {
      if (file === '.store') return;
      const fullPath = path.join(dirPath, file);
      try {
        if (fs.statSync(fullPath).isDirectory()) {
          arrayOfFiles = getAllFiles(fullPath, arrayOfFiles);
        } else {
          arrayOfFiles.push(fullPath);
        }
      } catch (e) {
        console.error(`[INDEX] Erro ao acessar ${fullPath}:`, e.message);
      }
    });
    return arrayOfFiles;
  };

  const allFiles = getAllFiles(uploadFolder);
  console.log(`[INDEX] Verificando ${allFiles.length} arquivos existentes...`);
  
  let processed = 0;
  for (const filePath of allFiles) {
    try {
      const hash = await calculateHash(filePath);
      const masterPath = path.join(storeFolder, hash);

      if (!fs.existsSync(masterPath)) {
        // Primeiro arquivo com este hash vira o master
        fs.renameSync(filePath, masterPath);
        try {
          fs.linkSync(masterPath, filePath);
        } catch (e) {
          fs.copyFileSync(masterPath, filePath);
        }
      } else {
        // Se já existe um master, mas este arquivo não é um link para ele
        const stat = fs.statSync(filePath);
        const masterStat = fs.statSync(masterPath);
        
        if (stat.ino !== masterStat.ino) {
          // São arquivos diferentes com mesmo conteúdo, unificar!
          try {
            // Tenta criar o link primeiro em um local temporário para garantir que funciona
            const tempLinkPath = filePath + '.tmp';
            fs.linkSync(masterPath, tempLinkPath);
            // Se funcionou, substitui o original
            fs.unlinkSync(filePath);
            fs.renameSync(tempLinkPath, filePath);
            console.log(`[INDEX] Unificado (Hard Link): ${filePath}`);
          } catch (linkErr) {
            // Se falhar o hard link, não fazemos nada (mantemos as cópias separadas para não perder dados)
            console.log(`[INDEX] Falha ao unificar ${filePath}: ${linkErr.message}`);
          }
        }
      }
      fileHashes[hash] = masterPath;
      processed++;
      if (processed % 10 === 0) console.log(`[INDEX] Progresso: ${processed}/${allFiles.length}`);
    } catch (e) {
      console.error(`[INDEX] Erro ao processar ${filePath}:`, e);
    }
  }
  saveHashes();
  console.log(`[INDEX] Indexação concluída. ${processed} arquivos processados.`);
  return { total: allFiles.length, processed };
}

// Função para remover arquivos do .store que não possuem mais links
async function cleanupStore() {
  console.log('[CLEANUP] Iniciando limpeza do .store...');
  const files = fs.readdirSync(storeFolder);
  let removed = 0;
  let kept = 0;

  for (const file of files) {
    const fullPath = path.join(storeFolder, file);
    try {
      const stats = fs.statSync(fullPath);
      // Se nlink for 1, significa que apenas a entrada no .store existe
      if (stats.nlink === 1) {
        fs.unlinkSync(fullPath);
        // Remover do mapeamento de hashes se existir
        for (const hash in fileHashes) {
          if (fileHashes[hash] === fullPath) {
            delete fileHashes[hash];
          }
        }
        removed++;
      } else {
        kept++;
      }
    } catch (e) {
      console.error(`[CLEANUP] Erro ao processar ${file}:`, e.message);
    }
  }
  saveHashes();
  console.log(`[CLEANUP] Concluído. Removidos: ${removed}, Mantidos: ${kept}`);
  return { removed, kept };
}

// Removido a chamada solta aqui para ser chamada dentro da função start()
// indexExistingFiles();

const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());


// Configuração do Multer para usar uma pasta temporária isolada
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    // Salva primeiro em uma pasta temp para evitar que o indexador automático
    // "roube" o arquivo antes do processamento terminar
    cb(null, tempFolder);
  },
  filename: function(req, file, cb) {
    // Sanitiza o nome original do arquivo
    const safeName = sanitizeName(file.originalname);
    cb(null, Date.now() + '-' + safeName);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // Limite de 100MB para compatibilidade com Cloudflare
  fileFilter: function(req, file, cb) {
    const allowedTypes = [
      'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml',
      'video/mp4', 'video/quicktime', 'video/webm', 'video/x-m4v', 'video/x-matroska', 'video/avi', 'video/mpeg', 'video/x-msvideo',
      'audio/mpeg', 'audio/mp3', 'audio/wav', 'audio/ogg', 'audio/aac',
      'application/octet-stream' // Permitir genérico para vídeos/áudios não identificados
    ];
    
    const isAllowedMime = allowedTypes.includes(file.mimetype);
    const isAllowedExt = /\.(mp4|mov|webm|m4v|mkv|avi|mpg|mpeg|mp3|wav|ogg|aac|jpg|jpeg|png|gif|webp|svg)$/i.test(file.originalname);

    if (isAllowedMime || isAllowedExt) {
      cb(null, true);
    } else {
      console.log(`[UPLOAD] Bloqueado: Mimetype "${file.mimetype}" ou Extensão não permitida para "${file.originalname}"`);
      cb(new Error('Tipo de arquivo não permitido: ' + file.mimetype));
    }
  }
});

// Middleware de autenticação por API key (aceita via Header ou Token na URL)
function apiKeyMiddleware(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.query.key;
  
  // 1. Verificar se é a chave mestra (para upload, delete, list e acesso total)
  if (apiKey && apiKey === process.env.API_KEY) {
    return next();
  }

  // 2. Verificar se é um Token Fixo (para visualização de arquivos)
  // Se o middleware for usado via app.use('/files', ...), o req.path é relativo à raiz de uploads
  // Se for usado em rotas como /list ou /delete, o req.path é /list ou /delete
  let relativePath = req.path;
  
  // Se o caminho começar com /files/, removemos para obter o caminho do arquivo
  if (relativePath.startsWith('/files/')) {
    relativePath = relativePath.replace('/files/', '');
  } 
  // Remove a barra inicial se existir
  if (relativePath.startsWith('/')) {
    relativePath = relativePath.substring(1);
  }

  const { token } = req.query;
  if (token && verifyPermanentToken(decodeURIComponent(relativePath), token)) {
    return next();
  }

  // Log detalhado para debug (ajuda a identificar por que falhou)
  console.log(`[AUTH] Negado: ${req.method} ${req.originalUrl}`);
  if (!apiKey && !token) {
    console.log(`  -> Motivo: Nenhuma credencial fornecida (Header x-api-key ou ?token= ausentes)`);
  } else if (apiKey && apiKey !== process.env.API_KEY) {
    console.log(`  -> Motivo: API Key inválida`);
  } else if (token) {
    console.log(`  -> Motivo: Token inválido para o caminho: ${relativePath}`);
  }

  res.status(401).json({ error: 'Não autorizado' });
}

// Endpoint para upload (protegido, suporta subpastas)
app.post('/upload', apiKeyMiddleware, function(req, res) {
  console.log(`[UPLOAD] Início da recepção do arquivo...`);
  upload.single('file')(req, res, async function(err) {
    if (err instanceof multer.MulterError) {
      console.error('[UPLOAD] Erro do Multer:', err);
      let msg = err.message;
      if (err.code === 'LIMIT_FILE_SIZE') {
        msg = 'Arquivo muito grande. O limite máximo permitido é de 100MB.';
      }
      return res.status(400).json({ error: msg });
    } else if (err) {
      console.error('[UPLOAD] Erro:', err);
      return res.status(400).json({ error: err.message });
    }

    try {
      if (!req.file) {
        return res.status(400).json({ error: 'Nenhum arquivo enviado' });
      }

      const folder = sanitizeName(req.query.folder, true);
      const tempFilePath = req.file.path;
      const mimetype = req.file.mimetype;
      const size = req.file.size;

      // Definir limites específicos por tipo
      let limit = 50 * 1024 * 1024; // 50MB para imagens, gifs e músicas
      let typeLabel = 'imagem/áudio';

      if (mimetype.startsWith('video/') || /\.(mp4|mov|webm|m4v|mkv|avi|mpg|mpeg)$/i.test(req.file.originalname)) {
        limit = 100 * 1024 * 1024; // 100MB para vídeos (Limite Cloudflare)
        typeLabel = 'vídeo';
      }

      if (size > limit) {
        if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
        return res.status(400).json({ 
          error: `Arquivo muito grande para o tipo ${typeLabel}. Limite: ${limit / (1024 * 1024)}MB` 
        });
      }

      const fileHash = await calculateHash(tempFilePath);
      
      const masterPath = path.join(storeFolder, fileHash);
      const relativePath = (folder ? folder + '/' : '') + req.file.filename;
      const targetPath = path.join(uploadFolder, relativePath);

      // Garantir que a pasta de destino existe
      const destDir = path.dirname(targetPath);
      if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });

      // 1. Garantir que temos o "Master" no .store
      if (!fs.existsSync(masterPath)) {
        // Move o arquivo da pasta temp para o store
        try {
          fs.renameSync(tempFilePath, masterPath);
        } catch (renameErr) {
          // Fallback para cópia se o rename falhar (ex: partições diferentes)
          fs.copyFileSync(tempFilePath, masterPath);
          if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
        }
      } else {
        // Já temos esse conteúdo, deleta o temporário da pasta temp
        if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
      }

      // 2. Criar um Hard Link do Master para o local de destino final
      try {
        if (fs.existsSync(targetPath)) fs.unlinkSync(targetPath);
        fs.linkSync(masterPath, targetPath);
        console.log(`[UPLOAD] Link criado: ${relativePath}`);
      } catch (linkErr) {
        fs.copyFileSync(masterPath, targetPath);
        console.log(`[UPLOAD] Cópia realizada (Fallback): ${relativePath}`);
      }

      // Registrar no mapeamento
      fileHashes[fileHash] = masterPath; 
      saveHashes();

      const token = generatePermanentToken(relativePath);
      const fileUrl = `${req.protocol}://${req.get('host')}/files/${relativePath.replace(/\\/g, '/')}?token=${token}`;
      
      console.log(`[UPLOAD] Arquivo processado: ${req.file.originalname} -> ${relativePath} (Hash: ${fileHash})`);
      res.json({ 
        message: 'Upload bem-sucedido', 
        url: fileUrl, 
        filename: req.file.filename, 
        folder, 
        duplicate: fs.existsSync(masterPath) 
      });
    } catch (err) {
      console.error('[UPLOAD] Erro interno:', err);
      res.status(500).json({ error: 'Erro ao processar upload' });
    }
  });
});


// Endpoint para listar arquivos (protegido)
app.get('/list', apiKeyMiddleware, function(req, res) {
  const getAllFiles = (dirPath, arrayOfFiles) => {
    const files = fs.readdirSync(dirPath);
    arrayOfFiles = arrayOfFiles || [];
    files.forEach(function(file) {
      // Ignorar a pasta interna de armazenamento (.store)
      if (file === '.store') return;

      const fullPath = path.join(dirPath, file);
      if (fs.statSync(fullPath).isDirectory()) {
        arrayOfFiles = getAllFiles(fullPath, arrayOfFiles);
      } else {
        const stats = fs.statSync(fullPath);
        const relativePath = path.relative(uploadFolder, fullPath).replace(/\\/g, '/');
        const token = generatePermanentToken(relativePath);
        const fileUrl = `${req.protocol}://${req.get('host')}/files/${relativePath}?token=${token}`;
        
        arrayOfFiles.push({
          name: file,
          path: relativePath,
          url: fileUrl,
          size: stats.size,
          mtime: stats.mtime,
          ino: stats.ino // Adicionado para identificar Hard Links
        });
      }
    });
    return arrayOfFiles;
  };

  try {
    const fileList = getAllFiles(uploadFolder);
    res.json(fileList);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar arquivos' });
  }
});


// Endpoint para remoção de arquivos (protegido, suporta subpastas) - recebe caminho ou URL via body JSON
app.delete('/delete', apiKeyMiddleware, function(req, res) {
  let relPath = req.body.filepath || '';
  const urlStr = req.body.url || '';

  // Se uma URL for fornecida, extrair o caminho relativo do arquivo
  if (urlStr) {
    try {
      // Tenta tratar como URL completa ou apenas o caminho
      const urlObj = urlStr.startsWith('http') ? new URL(urlStr) : { pathname: urlStr };
      let pathname = decodeURIComponent(urlObj.pathname);
      
      // Remove o prefixo /files/ se existir
      if (pathname.includes('/files/')) {
        relPath = pathname.split('/files/')[1];
      } else {
        relPath = pathname.startsWith('/') ? pathname.substring(1) : pathname;
      }
      
      // Remove query strings (como ?token=...) se ainda existirem
      relPath = relPath.split('?')[0];
    } catch (e) {
      console.error('[DELETE] Erro ao processar URL:', e.message);
    }
  }

  if (!relPath) {
    console.log('[DELETE] Falha: filepath ou url não informados');
    return res.status(400).json({ error: 'filepath ou url obrigatório no corpo da requisição' });
  }

  // Sanitizar o caminho para evitar Directory Traversal e nomes bugados
  const safePath = sanitizeName(relPath, true).split('/').join(path.sep);
  const filePath = path.join(uploadFolder, safePath);
  
  fs.access(filePath, fs.constants.F_OK, (err) => {
    if (err) {
      console.log(`[DELETE] Arquivo não encontrado: ${filePath}`);
      return res.status(404).json({ error: 'Arquivo não encontrado' });
    }
    fs.unlink(filePath, (err) => {
      if (err) {
        console.log(`[DELETE] Erro ao remover: ${filePath}`);
        return res.status(500).json({ error: 'Erro ao remover arquivo' });
      }
      
      console.log(`[DELETE] Removido: ${filePath}`);
      res.json({ message: 'Arquivo removido com sucesso' });
    });
  });
});


// Endpoint para sanitização manual (re-indexa e limpa .store)
app.post('/sanitize', apiKeyMiddleware, async function(req, res) {
  try {
    console.log('[SANITIZE] Iniciando sanitização manual...');
    const indexStats = await indexExistingFiles();
    const cleanupStats = await cleanupStore();
    
    res.json({
      message: 'Sanitização concluída',
      index: indexStats,
      cleanup: cleanupStats
    });
  } catch (err) {
    console.error('[SANITIZE] Erro:', err);
    res.status(500).json({ error: 'Erro durante a sanitização' });
  }
});


// Servir arquivos da pasta uploads e subpastas (protegido por API Key)
app.use('/files', apiKeyMiddleware, express.static(uploadFolder));

// Teste de API
app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Rodar servidor HTTP
const PORT = process.env.PORT || 3000;
const server = http.createServer(app);

// Aumentar timeouts para suportar uploads grandes e lentos
server.timeout = 600000; // 10 minutos
server.keepAliveTimeout = 61000; // Um pouco mais que o padrão de proxies (60s)
server.headersTimeout = 62000;

async function start() {
  // Aguarda a indexação inicial antes de abrir o servidor
  await indexExistingFiles();
  
  server.listen(PORT, '0.0.0.0', function() {
    console.log('Servidor rodando na porta ' + PORT);
  });
}

start();