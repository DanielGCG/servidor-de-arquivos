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
if (!fs.existsSync(uploadFolder)) fs.mkdirSync(uploadFolder);
if (!fs.existsSync(storeFolder)) fs.mkdirSync(storeFolder, { recursive: true });

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

// Funções para URLs com Tokens Fixos (Segurança sem expiração)
function generatePermanentToken(relativePath) {
  // Gera um hash único para o arquivo usando a API_KEY como segredo
  // Isso torna a URL fixa, mas impossível de prever sem a chave
  return crypto
    .createHmac('sha256', process.env.API_KEY)
    .update(relativePath)
    .digest('hex')
    .substring(0, 16); // 16 caracteres são suficientes para segurança e mantêm a URL curta
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
      if (fs.statSync(fullPath).isDirectory()) {
        arrayOfFiles = getAllFiles(fullPath, arrayOfFiles);
      } else {
        arrayOfFiles.push(fullPath);
      }
    });
    return arrayOfFiles;
  };

  const allFiles = getAllFiles(uploadFolder);
  console.log(`[INDEX] Verificando ${allFiles.length} arquivos existentes...`);
  
  for (const filePath of allFiles) {
    try {
      const hash = await calculateHash(filePath);
      const masterPath = path.join(storeFolder, hash);

      if (!fs.existsSync(masterPath)) {
        // Primeiro arquivo com este hash vira o master
        fs.renameSync(filePath, masterPath);
        fs.linkSync(masterPath, filePath);
      } else {
        // Se já existe um master, mas este arquivo não é um link para ele
        const stat = fs.statSync(filePath);
        const masterStat = fs.statSync(masterPath);
        
        if (stat.ino !== masterStat.ino) {
          // São arquivos diferentes com mesmo conteúdo, unificar!
          fs.unlinkSync(filePath);
          fs.linkSync(masterPath, filePath);
          console.log(`[INDEX] Unificado: ${filePath}`);
        }
      }
      fileHashes[hash] = masterPath;
    } catch (e) {
      console.error(`[INDEX] Erro ao processar ${filePath}:`, e);
    }
  }
  saveHashes();
  console.log(`[INDEX] Indexação concluída.`);
}

indexExistingFiles();

const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());


// Configuração do Multer para suportar subpastas
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    let folder = req.query.folder || '';
    // Sanitizar nome da pasta
    folder = folder.replace(/[^a-zA-Z0-9-_]/g, '');
    const dest = path.join(uploadFolder, folder);
    if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
    cb(null, dest);
  },
  filename: function(req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 500 * 1024 * 1024 }, // Limite máximo global (500MB para vídeos)
  fileFilter: function(req, file, cb) {
    const allowedTypes = [
      'image/jpeg', 'image/png', 'image/gif', 'image/webp',
      'video/mp4', 'video/quicktime', 'video/webm', 'video/x-m4v',
      'audio/mpeg', 'audio/mp3', 'audio/wav'
    ];
    
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      console.log(`[UPLOAD] Bloqueado: Mimetype "${file.mimetype}" não permitido para o arquivo "${file.originalname}"`);
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
app.post('/upload', apiKeyMiddleware, upload.single('file'), async function(req, res) {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Nenhum arquivo enviado' });
    }

    const folder = req.query.folder ? req.query.folder.replace(/[^a-zA-Z0-9-_]/g, '') : '';
    const tempFilePath = req.file.path;
    const mimetype = req.file.mimetype;
    const size = req.file.size;

    // Definir limites específicos por tipo
    let limit = 25 * 1024 * 1024; // 25MB para imagens, gifs e músicas
    let typeLabel = 'imagem/áudio';

    if (mimetype.startsWith('video/')) {
      limit = 500 * 1024 * 1024; // 500MB para vídeos
      typeLabel = 'vídeo';
    }

    if (size > limit) {
      fs.unlinkSync(tempFilePath); // Remove o arquivo que excedeu o limite específico
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
      // Move o arquivo temporário para o store (primeira vez que vemos este conteúdo)
      fs.renameSync(tempFilePath, masterPath);
    } else {
      // Já temos esse conteúdo, deleta o temporário
      fs.unlinkSync(tempFilePath);
    }

    // 2. Criar um Hard Link do Master para o local de destino do usuário
    // Isso cria um "ponteiro" real no sistema de arquivos que não ocupa espaço extra
    try {
      fs.linkSync(masterPath, targetPath);
      console.log(`[UPLOAD] Link criado (Espaço economizado): ${relativePath}`);
    } catch (linkErr) {
      // Se falhar (ex: partições diferentes), faz uma cópia normal
      fs.copyFileSync(masterPath, targetPath);
      console.log(`[UPLOAD] Cópia realizada (Partições diferentes): ${relativePath}`);
    }

    // Registrar no mapeamento (opcional, mas útil para busca rápida)
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
    console.error('[UPLOAD] Erro:', err);
    res.status(500).json({ error: 'Erro ao processar upload' });
  }
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


// Endpoint para remoção de arquivos (protegido, suporta subpastas) - recebe caminho via body JSON
app.delete('/delete', apiKeyMiddleware, function(req, res) {
  const relPath = req.body.filepath || '';
  if (!relPath) {
    console.log('[DELETE] Falha: filepath não informado no corpo da requisição');
    return res.status(400).json({ error: 'filepath obrigatório no corpo da requisição' });
  }
  // Sanitizar cada parte do caminho (permitindo espaços, que são comuns em nomes de arquivos)
  const safePath = relPath.split('/').map(p => p.replace(/[^a-zA-Z0-9-_ .]/g, '')).join(path.sep);
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


// Servir arquivos da pasta uploads e subpastas (protegido por API Key)
app.use('/files', apiKeyMiddleware, express.static(uploadFolder));

// Teste de API
app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Rodar servidor HTTP simples
const PORT = process.env.PORT || 3000;
http.createServer(app).listen(PORT, '0.0.0.0', function() {
  console.log('Servidor rodando na porta ' + PORT);
});