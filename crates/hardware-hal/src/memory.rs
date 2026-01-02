//! Secure memory management
//!
//! Provides memory security primitives for all hardware backends

use crate::{HardwareError, HardwareResult};
use zeroize::Zeroizing;

/// Secure memory allocator with automatic zeroization
pub struct SecureMemory {
    /// Memory buffer
    buffer: Zeroizing<Vec<u8>>,
}

impl SecureMemory {
    /// Allocate secure memory
    pub fn new(size: usize) -> Self {
        SecureMemory {
            buffer: Zeroizing::new(vec![0u8; size]),
        }
    }

    /// Get mutable reference to buffer
    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    /// Get immutable reference to buffer
    pub fn as_ref(&self) -> &[u8] {
        &self.buffer
    }

    /// Copy data into secure memory
    pub fn copy_from(&mut self, data: &[u8]) -> HardwareResult<()> {
        if data.len() > self.buffer.len() {
            return Err(HardwareError::InvalidParameter(
                "Data too large for buffer".to_string()
            ));
        }

        self.buffer[..data.len()].copy_from_slice(data);
        Ok(())
    }
}

/// Memory protection levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProtection {
    /// Read-write access
    ReadWrite,
    /// Read-only access
    ReadOnly,
    /// No access (secret data)
    NoAccess,
}

/// Guard rails for preventing memory disclosure
pub struct MemoryGuard;

impl MemoryGuard {
    /// Verify no secrets in debug output
    pub fn sanitize_debug_output(output: &str) -> String {
        // Remove potential secret material from debug output
        output
            .replace(|c: char| c.is_ascii_hexdigit(), "*")
            .to_string()
    }

    /// Constant-time equality check
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }

        diff == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_memory() {
        let mut mem = SecureMemory::new(32);
        let data = b"secret data";

        mem.copy_from(data).unwrap();
        assert_eq!(&mem.as_ref()[..data.len()], data);

        // Drop will zeroize
    }

    #[test]
    fn test_constant_time_eq() {
        let a = b"secret";
        let b = b"secret";
        let c = b"public";

        assert!(MemoryGuard::constant_time_eq(a, b));
        assert!(!MemoryGuard::constant_time_eq(a, c));
    }
}
