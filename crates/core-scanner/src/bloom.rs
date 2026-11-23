use std::hash::{Hash, Hasher};

/// Space-efficient probabilistic filter for fast-negative membership queries.
#[derive(Debug, Clone)]
pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
    num_hashes: u32,
}

impl BloomFilter {
    /// Creates a Bloom filter with a given capacity in bits and number of hash functions.
    pub fn new(num_bits: usize, num_hashes: u32) -> Self {
        let num_words = (num_bits + 63) / 64;
        Self {
            bits: vec![0u64; num_words],
            num_bits,
            num_hashes,
        }
    }

    /// Default 1MB filter (~8 million bits, 5 hashes) for low RAM footprint (< 2 MB).
    pub fn default_fast() -> Self {
        Self::new(8 * 1024 * 1024, 5)
    }

    fn get_hash<T: Hash + ?Sized>(&self, item: &T, seed: u64) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        seed.hash(&mut hasher);
        item.hash(&mut hasher);
        (hasher.finish() as usize) % self.num_bits
    }

    pub fn insert<T: Hash + ?Sized>(&mut self, item: &T) {
        for seed in 0..self.num_hashes {
            let bit_idx = self.get_hash(item, seed as u64);
            let word_idx = bit_idx / 64;
            let bit_offset = bit_idx % 64;
            self.bits[word_idx] |= 1u64 << bit_offset;
        }
    }

    pub fn contains<T: Hash + ?Sized>(&self, item: &T) -> bool {
        for seed in 0..self.num_hashes {
            let bit_idx = self.get_hash(item, seed as u64);
            let word_idx = bit_idx / 64;
            let bit_offset = bit_idx % 64;
            if (self.bits[word_idx] & (1u64 << bit_offset)) == 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_membership() {
        let mut bloom = BloomFilter::new(1024, 4);
        bloom.insert("kernel32.dll");
        bloom.insert("ntdll.dll");

        assert!(bloom.contains("kernel32.dll"));
        assert!(bloom.contains("ntdll.dll"));
        assert!(!bloom.contains("malware_trojan.exe"));
    }
}
