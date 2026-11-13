// SPDX-FileCopyrightText: 2023-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::path::{Component, Path, PathBuf};

use thiserror::Error;

/// Path safety-related errors.
#[derive(Clone, Debug, Error)]
pub enum PathSafetyError {
    #[error("Path contains multiple components: {0:?}")]
    NotSingle(PathBuf),
    #[error("Path contains '..': {0:?}")]
    HasDotDot(PathBuf),
}

pub trait PathExt {
    /// Get the non-empty parent of the path. If the path has no parent in the
    /// string, then `.` is returned. This does not perform any filesystem
    /// operations.
    fn parent_or_dot(&self) -> &Path;

    /// Join `self` with `child`, disallowing unsafe child paths. Absolute child
    /// paths are converted into relative paths and `..` components result in an
    /// error.
    fn join_safe(&self, child: impl AsRef<Path>) -> Result<PathBuf, PathSafetyError>;

    /// Ensure that this path is a single non-`.`, non-`..` component.
    fn ensure_single(&self) -> Result<(), PathSafetyError>;

    /// Like [`Self::join_safe`], but ensures that the child path is a single
    /// non-`.`, non-`..` component via [`Self::ensure_single`].
    fn join_single(&self, child: impl AsRef<Path>) -> Result<PathBuf, PathSafetyError>;
}

impl PathExt for Path {
    fn parent_or_dot(&self) -> &Path {
        if let Some(parent) = self.parent()
            && !parent.as_os_str().is_empty()
        {
            return parent;
        }

        Self::new(".")
    }

    fn join_safe(&self, child: impl AsRef<Self>) -> Result<PathBuf, PathSafetyError> {
        fn inner(parent: &Path, child: &Path) -> Result<PathBuf, PathSafetyError> {
            let mut result = parent.to_owned();

            for component in child.components() {
                match component {
                    // Make absolute paths relative.
                    Component::Prefix(_) | Component::RootDir | Component::CurDir => continue,
                    // Unsafe path. We block this even if it wouldn't escape the
                    // parent.
                    Component::ParentDir => {
                        return Err(PathSafetyError::HasDotDot(child.to_path_buf()));
                    }
                    Component::Normal(os_str) => result.push(os_str),
                }
            }

            Ok(result)
        }

        inner(self, child.as_ref())
    }

    fn ensure_single(&self) -> Result<(), PathSafetyError> {
        // Path::file_name() already checks for `.` and `..`.
        if self.file_name() != Some(self.as_os_str()) {
            return Err(PathSafetyError::NotSingle(self.to_path_buf()));
        }

        Ok(())
    }

    fn join_single(&self, child: impl AsRef<Self>) -> Result<PathBuf, PathSafetyError> {
        child.as_ref().ensure_single()?;
        self.join_safe(child.as_ref())
    }
}
