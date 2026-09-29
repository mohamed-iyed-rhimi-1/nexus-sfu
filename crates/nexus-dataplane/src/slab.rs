//! Slab storage for sessions, tracks and subscriptions (note §7.1).
//!
//! Entries grow only in command handling. Keys carry a generation so a key
//! kept after its entry was removed is caught in debug builds; removal is
//! eager, so none should exist.

/// Key of a slab entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Key {
    index: u32,
    gen: u32,
}

struct Slot<T> {
    gen: u32,
    value: Option<T>,
}

/// Bytes one slot of a `Slab<T>` takes (the memory bench's report).
pub const fn slot_size<T>() -> usize {
    std::mem::size_of::<Slot<T>>()
}

/// `Vec` of slots plus a free list.
pub struct Slab<T> {
    slots: Vec<Slot<T>>,
    free: Vec<u32>,
    len: usize,
}

impl<T> Slab<T> {
    /// An empty slab (no allocation until the first insert).
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            len: 0,
        }
    }

    /// Live entries.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Slots, live or free (bounds a sweep over the slab).
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// The key of slot `index` if it holds an entry.
    pub fn key_at(&self, index: usize) -> Option<Key> {
        let slot = self.slots.get(index)?;
        slot.value.as_ref()?;
        Some(Key {
            index: index as u32,
            gen: slot.gen,
        })
    }

    /// Stores `value` (command path: may allocate).
    pub fn insert(&mut self, value: T) -> Key {
        let key = match self.free.pop() {
            Some(index) => {
                let slot = &mut self.slots[index as usize];
                assert!(slot.value.is_none());
                slot.gen = slot.gen.wrapping_add(1);
                slot.value = Some(value);
                Key {
                    index,
                    gen: slot.gen,
                }
            }
            None => {
                let index = u32::try_from(self.slots.len()).expect("slab index fits u32");
                self.slots.push(Slot {
                    gen: 0,
                    value: Some(value),
                });
                Key { index, gen: 0 }
            }
        };
        self.len += 1;
        key
    }

    /// Removes and returns the entry.
    pub fn remove(&mut self, key: Key) -> T {
        let slot = &mut self.slots[key.index as usize];
        assert!(slot.gen == key.gen, "stale slab key");
        let value = slot.value.take().expect("slab entry present");
        self.free.push(key.index);
        self.len -= 1;
        value
    }

    /// The entry of a live key.
    pub fn get(&self, key: Key) -> &T {
        let slot = &self.slots[key.index as usize];
        debug_assert!(slot.gen == key.gen, "stale slab key");
        slot.value.as_ref().expect("slab entry present")
    }

    /// The entry of a live key, writable.
    pub fn get_mut(&mut self, key: Key) -> &mut T {
        let slot = &mut self.slots[key.index as usize];
        debug_assert!(slot.gen == key.gen, "stale slab key");
        slot.value.as_mut().expect("slab entry present")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_remove_reuse() {
        let mut slab = Slab::new();
        let a = slab.insert(1);
        let b = slab.insert(2);
        assert_eq!(slab.len(), 2);
        assert_eq!(slab.remove(a), 1);
        let c = slab.insert(3);
        assert_ne!(a, c, "reused slot has a new generation");
        assert_eq!(*slab.get(b), 2);
        assert_eq!(*slab.get(c), 3);
        assert_eq!(slab.len(), 2);
        let live: Vec<Key> = (0..slab.slot_count())
            .filter_map(|i| slab.key_at(i))
            .collect();
        assert_eq!(live, vec![c, b]);
        slab.remove(b);
        assert_eq!(slab.key_at(1), None);
    }

    #[test]
    #[should_panic(expected = "stale slab key")]
    fn stale_key_is_caught() {
        let mut slab = Slab::new();
        let a = slab.insert(1);
        slab.remove(a);
        let _ = slab.insert(2);
        slab.remove(a);
    }
}
