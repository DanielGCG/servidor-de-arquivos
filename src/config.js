const fs = require('fs');
const path = require('path');

const configPath = path.join(__dirname, '../storage_config.json');
const hashesFile = path.join(__dirname, '../hashes.json');

// Global state
let state = {
  uploadFolder: path.join(__dirname, '../uploads'),
  storeFolder: '',
  fileHashes: {}
};

function initConfig() {
  if (fs.existsSync(configPath)) {
    try {
      const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      if (config.uploadFolder) {
        state.uploadFolder = config.uploadFolder;
      }
    } catch (e) {
      console.error('Erro ao ler storage_config.json:', e);
    }
  }

  state.storeFolder = path.join(state.uploadFolder, '.store');
  
  if (!fs.existsSync(state.uploadFolder)) fs.mkdirSync(state.uploadFolder, { recursive: true });
  if (!fs.existsSync(state.storeFolder)) fs.mkdirSync(state.storeFolder, { recursive: true });

  if (fs.existsSync(hashesFile)) {
    try {
      state.fileHashes = JSON.parse(fs.readFileSync(hashesFile, 'utf8'));
    } catch (e) {
      state.fileHashes = {};
    }
  }
}

function saveConfig(newRoot) {
  state.uploadFolder = newRoot;
  state.storeFolder = path.join(newRoot, '.store');
  fs.writeFileSync(configPath, JSON.stringify({ uploadFolder: newRoot }, null, 2));
}

function saveHashes() {
  fs.writeFileSync(hashesFile, JSON.stringify(state.fileHashes, null, 2));
}

function clearHashes() {
  state.fileHashes = {};
  saveHashes();
}

module.exports = {
  state,
  initConfig,
  saveConfig,
  saveHashes,
  clearHashes
};
