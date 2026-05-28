//! A simple bitmask implementation for tracking free/used items in a pool.

pub struct Bitmask {
    size: usize,
    bits: Box<[u32]>,
}

impl Bitmask {
    pub fn new(size: usize) -> Self {
        let num_words = size.div_ceil(32);
        Self {
            size,
            bits: vec![0; num_words].into_boxed_slice(),
        }
    }

    pub fn is_set(&self, idx: usize) -> bool {
        assert!(idx < self.size);
        let word = idx / 32;
        let bit = idx % 32;
        (self.bits[word] & (1 << bit)) != 0
    }

    pub fn set(&mut self, idx: usize) {
        assert!(idx < self.size);
        let word = idx / 32;
        let bit = idx % 32;
        self.bits[word] |= 1 << bit;
    }

    pub fn clear(&mut self, idx: usize) {
        assert!(idx < self.size);
        let word = idx / 32;
        let bit = idx % 32;
        self.bits[word] &= !(1 << bit);
    }

    pub fn size(&self) -> usize {
        self.size
    }
}
