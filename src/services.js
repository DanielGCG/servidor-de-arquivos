const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('./config');

function calculateHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', data => hash.update(data));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', err => reject(err));
  });
}

async function indexExistingFiles() {
  const { uploadFolder, storeFolder, fileHashes } = config.state;
  
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
        fs.renameSync(filePath, masterPath);
        try {
          fs.linkSync(masterPath, filePath);
        } catch (e) {
          fs.copyFileSync(masterPath, filePath);
        }
      } else {
        const stat = fs.statSync(filePath);
        const masterStat = fs.statSync(masterPath);
        
        if (stat.ino !== masterStat.ino) {
          try {
            const tempLinkPath = filePath + '.tmp';
            fs.linkSync(masterPath, tempLinkPath);
            fs.unlinkSync(filePath);
            fs.renameSync(tempLinkPath, filePath);
            console.log(`[INDEX] Unificado (Hard Link): ${filePath}`);
          } catch (linkErr) {
            console.log(`[INDEX] Falha ao unificar ${filePath}: ${linkErr.message}`);
          }
        }
      }
      fileHashes[hash] = masterPath;
      processed++;
    } catch (e) {
      console.error(`[INDEX] Erro ao processar ${filePath}:`, e);
    }
  }
  config.saveHashes();
  console.log(`[INDEX] Indexação concluída. ${processed} arquivos processados.`);
  return { total: allFiles.length, processed };
}

async function cleanupStore() {
  const { storeFolder, fileHashes } = config.state;
  console.log('[CLEANUP] Iniciando limpeza do .store...');
  const files = fs.readdirSync(storeFolder);
  let removed = 0;
  let kept = 0;

  for (const file of files) {
    const fullPath = path.join(storeFolder, file);
    try {
      const stats = fs.statSync(fullPath);
      if (stats.nlink === 1) {
        fs.unlinkSync(fullPath);
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
  config.saveHashes();
  console.log(`[CLEANUP] Concluído. Removidos: ${removed}, Mantidos: ${kept}`);
  return { removed, kept };
}

let migrationState = {
  isMigrating: false,
  status: '',
  progress: 0,
  totalFiles: 0,
  filesProcessed: 0,
  error: null
};

function getMigrationState() {
  return migrationState;
}

function startMigration(newRoot) {
  if (migrationState.isMigrating) {
    throw new Error('Uma migração já está em andamento.');
  }

  const normalizedNewRoot = path.normalize(newRoot);
  if (!fs.existsSync(normalizedNewRoot)) {
    fs.mkdirSync(normalizedNewRoot, { recursive: true });
  }
  const testFile = path.join(normalizedNewRoot, '.testwrite');
  fs.writeFileSync(testFile, 'test');
  fs.unlinkSync(testFile);

  migrationState = {
    isMigrating: true,
    status: 'Iniciando cópia de arquivos...',
    progress: 0,
    totalFiles: 0,
    filesProcessed: 0,
    error: null
  };

  setTimeout(async () => {
    try {
      const { uploadFolder } = config.state;
      const getAllFiles = (dirPath, arrayOfFiles) => {
        if (!fs.existsSync(dirPath)) return arrayOfFiles || [];
        const files = fs.readdirSync(dirPath);
        arrayOfFiles = arrayOfFiles || [];
        files.forEach(function(file) {
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
      migrationState.totalFiles = allFiles.length;

      for (const oldPath of allFiles) {
        const relativePath = path.relative(uploadFolder, oldPath);
        const newPath = path.join(normalizedNewRoot, relativePath);
        
        const newDir = path.dirname(newPath);
        if (!fs.existsSync(newDir)) {
          fs.mkdirSync(newDir, { recursive: true });
        }

        fs.copyFileSync(oldPath, newPath);
        
        migrationState.filesProcessed++;
        migrationState.progress = Math.round((migrationState.filesProcessed / migrationState.totalFiles) * 50);
        migrationState.status = `Copiando: ${relativePath}`;
      }
      
      // Update config
      config.saveConfig(normalizedNewRoot);
      config.clearHashes();

      migrationState.status = 'Deduplicando arquivos copiados (recriando links)...';
      await indexExistingFiles();
      await cleanupStore();

      migrationState.progress = 100;
      migrationState.status = 'Migração concluída com sucesso!';
      migrationState.isMigrating = false;

    } catch (e) {
      console.error('[MIGRATE] Erro fatal:', e);
      migrationState.error = e.message;
      migrationState.isMigrating = false;
      migrationState.status = 'Erro na migração';
    }
  }, 1000);
}

module.exports = {
  calculateHash,
  indexExistingFiles,
  cleanupStore,
  startMigration,
  getMigrationState
};
