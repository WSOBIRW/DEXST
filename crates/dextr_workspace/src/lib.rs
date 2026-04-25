
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DextrWorkspace {
    pub root: PathBuf,
    pub dextr_dir: PathBuf,
    pub config_path: PathBuf,
    pub ai_memory_dir: PathBuf,
    pub audit_dir: PathBuf,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
}

impl DextrWorkspace {
    pub fn open(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        let dextr_dir = root.join(".dextr");

        let workspace = Self {
            config_path: dextr_dir.join("config.toml"),
            ai_memory_dir: dextr_dir.join("ai_memory"),
            audit_dir: dextr_dir.join("audit"),
            state_dir: dextr_dir.join("state"),
            cache_dir: dextr_dir.join("cache"),
            dextr_dir,
            root,
        };

        workspace.bootstrap()?;
        Ok(workspace)
    }

    fn bootstrap(&self) -> io::Result<()> {
        fs::create_dir_all(&self.dextr_dir)?;
        fs::create_dir_all(&self.ai_memory_dir)?;
        fs::create_dir_all(&self.audit_dir)?;
        fs::create_dir_all(&self.state_dir)?;
        fs::create_dir_all(&self.cache_dir)?;

        if !self.config_path.exists() {
            fs::write(
                &self.config_path,
                "[workspace]\nmode = \"observer\"\n\n[ai]\nenabled = false\n",
            )?;
        }

        Ok(())
    }
}
