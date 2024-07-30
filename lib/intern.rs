//! Interning objects used in tupfiles
//! Adapted from interment crate
#![deny(missing_docs)]

use std::any::Any;
use std::any::TypeId;
use std::borrow::Borrow;
use std::convert::AsRef;
use std::fmt::{Debug, Display, Pointer};
use std::hash::BuildHasher;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

use hashbrown::HashMap;
use parking_lot::Mutex;
use tinyset::Fits64;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A `TypeHolder` is a container for any sendable type.
pub struct TypeHolderSend(Vec<AnySend>);

/// `AnySend` is a wrapper around `Any` that is `Send`.
struct AnySend(Box<dyn Any + Send>);

struct HashSet<P>(HashMap<P, ()>);

impl<P: Deref + Eq + Hash> Default for HashSet<P> {
    fn default() -> Self {
        HashSet::new()
    }
}

impl<P> HashSet<P> {
    pub fn new() -> Self {
        HashSet(HashMap::new())
    }
}

impl<P: Deref + Eq + Hash> HashSet<P> {
    pub fn get<Q: Eq + Hash>(&self, key: &Q) -> Option<&P>
    where
        P::Target: Borrow<Q>,
    {
        let hash = {
            let mut hasher = self.0.hasher().build_hasher();
            key.hash(&mut hasher);
            hasher.finish()
        };
        self.0
            .raw_entry()
            .from_hash(hash, |k| <P::Target as Borrow<Q>>::borrow(k) == key)
            .as_ref()
            .map(|kv| kv.0)
    }
    pub fn _take<Q: Hash + Eq>(&mut self, k: &Q) -> Option<P>
    where
        P: Borrow<Q>,
    {
        self.0.remove_entry(k).map(|(a, ())| a)
        // let hash = {
        //     let mut hasher = self.0.hasher().build_hasher();
        //     key.hash(&mut hasher);
        //     hasher.finish()
        // };
        // let x = self.0.raw_entry_mut().from_hash(hash, |k| <P::Target as Borrow<Q>>::borrow(k) == key)
    }
    pub fn insert(&mut self, x: P) {
        self.0.insert(x, ());
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    #[cfg(feature = "bench")]
    pub fn clear(&mut self) {
        self.0.clear()
    }
}

impl TypeHolderSend {
    /// Get a reference to the type stored in this `TypeHolder`.
    pub fn get_type_mut<T: Any + Send + Default>(&mut self) -> &mut T {
        if let Some(i) = self
            .0
            .iter_mut()
            .position(|x| x.0.downcast_mut::<T>().is_some())
        {
            self.0[i].0.downcast_mut().unwrap()
        } else {
            let v: T = Default::default();
            self.0.push(AnySend(Box::new(v)));
            self.0.last_mut().unwrap().0.downcast_mut().unwrap()
        }
    }
    /// Create a new `TypeHolder`.
    pub const fn new() -> Self {
        TypeHolderSend(Vec::new())
    }
}

const INTERN_CONTAINER_COUNT: usize = 16;

/// A `Arena` is a container for `TypeHolder`s.
struct Arena {
    containers: [Mutex<TypeHolderSend>; INTERN_CONTAINER_COUNT],
}

/// Methods for `Arena`.
impl Arena {
    /// Create a new `Arena`.
    const fn new() -> Self {
        const EMPTY: Mutex<TypeHolderSend> = parking_lot::const_mutex(TypeHolderSend::new());
        Arena {
            containers: [EMPTY; INTERN_CONTAINER_COUNT],
        }
    }

    fn with<F, T, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
        T: Any + Send + Default,
    {
        // Compute the hash of the type.
        fn hash_of_type<T: 'static>() -> u64 {
            // We use very simple hasher, because it is optimized away to a constant:
            // https://rust.godbolt.org/z/4T1fa4GGs
            // which is not true for using `DefaultHasher`:
            // https://rust.godbolt.org/z/qKar1WKfz
            struct HasherForTypeId {
                hash: u64,
            }

            impl Hasher for HasherForTypeId {
                fn finish(&self) -> u64 {
                    self.hash
                }

                fn write(&mut self, bytes: &[u8]) {
                    // Hash for type only calls `write_u64` once,
                    // but handle this case explicitly to make sure
                    // this code doesn't break if stdlib internals change.

                    for byte in bytes {
                        self.hash = self.hash.wrapping_mul(31).wrapping_add(*byte as u64);
                    }
                }

                fn write_u64(&mut self, v: u64) {
                    self.hash = v;
                }
            }

            let mut hasher = HasherForTypeId { hash: 0 };
            TypeId::of::<T>().hash(&mut hasher);
            hasher.hash
        }

        f(
            self.containers[hash_of_type::<T>() as usize % INTERN_CONTAINER_COUNT]
                .lock()
                .get_type_mut(),
        )
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "intern")))]
/// A pointer to an interned object
///
/// An `Intern` points to an object that has been leaked and may be used in any
/// thread without locking.
pub struct Intern<T: 'static> {
    pointer: &'static T,
}

impl<T: 'static + Eq + Hash + Send + Sync + Display> Debug for Intern<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        //        write!(f, "{}", self.as_ref())
        Display::fmt(self, f)
    }
}

impl<T> Clone for Intern<T> {
    fn clone(&self) -> Self {
        Intern {
            pointer: self.pointer,
        }
    }
}

/// An `Intern` is `Copy`, which is unusual for a pointer.  This is safe
/// because we never free the data pointed to by an `Intern`.
impl<T> Copy for Intern<T> {}

impl<T> Intern<T> {
    fn get_pointer(&self) -> *const T {
        self.pointer as *const T
    }
}

static INTERN_CONTAINERS: Arena = Arena::new();

impl<T: Eq + Hash + Send + Sync + 'static> From<Box<T>> for Intern<T> {
    fn from(val: Box<T>) -> Self {
        INTERN_CONTAINERS.with(|m: &mut HashSet<&'static T>| -> Self {
            if let Some(&b) = m.get(val.borrow()) {
                return Intern { pointer: b };
            }
            let p: &'static T = Box::leak(Box::from(val));
            m.insert(p);
            Intern { pointer: p }
        })
    }
}

impl<T: Eq + Hash + Send + Sync + 'static> Intern<T> {
    /// Intern a value.
    ///
    /// If this value has not previously been interned, then `new` will allocate
    /// a spot for the value on the heap.  Otherwise, it will return a pointer
    /// to the object previously allocated.
    ///
    /// Note that `Intern::new` is a bit slow, since it needs to check a
    /// `HashSet` protected by a `Mutex`.
    pub fn new(val: T) -> Intern<T> {
        INTERN_CONTAINERS.with(|m: &mut HashSet<&'static T>| -> Intern<T> {
            if let Some(&b) = m.get(&val) {
                return Intern { pointer: b };
            }
            let p: &'static T = Box::leak(Box::new(val));
            m.insert(p);
            Intern { pointer: p }
        })
    }
    /// Only fetch an interned value if it exists
    pub fn fetch_interned(val: &T) -> Option<Intern<T>> {
        INTERN_CONTAINERS.with(|m: &mut HashSet<&'static T>| -> Option<Intern<T>> {
            m.get(val).and_then(|&b| Some(Intern { pointer: b }))
        })
    }
}

impl<T: Eq + Hash + Send + Sync + 'static> Intern<T> {
    /// Get a long-lived reference to the data pointed to by an `Intern`, which
    /// is never freed from the intern pool.
    pub fn as_ref(self) -> &'static T {
        self.pointer
    }
    /// See how many objects have been interned.  This may be helpful
    /// in analyzing memory use.
    pub fn num_objects_interned() -> usize {
        INTERN_CONTAINERS.with(|m: &mut HashSet<&'static T>| -> usize { m.len() })
    }
    /// Iterate over all interned objects and apply a function to each one.
    pub fn iter_interned<F>(mut f: F) -> Result<(), crate::errors::Error>
    where
        F: FnMut(Intern<T>) -> Result<(), crate::errors::Error>,
    {
        INTERN_CONTAINERS.with(
            |m: &mut HashSet<&'static T>| -> Result<(), crate::errors::Error> {
                m.0.keys()
                    .try_for_each(move |&k| -> Result<(), crate::errors::Error> {
                        f(Intern { pointer: k })
                    })
            },
        )
    }
    /// Check if a value has been interned.
    pub fn is_interned(t: &T) -> bool {
        INTERN_CONTAINERS.with(|m: &mut HashSet<&'static T>| -> bool { m.0.contains_key(&t) })
    }

    /// Only for benchmarking, this will cause problems
    #[cfg(feature = "bench")]
    pub fn benchmarking_only_clear_interns() {
        INTERN_CONTAINERS.with(|m: &mut HashSet<&'static T>| -> () { m.clear() })
    }
}

#[cold]
fn allocate_ptr() -> *mut usize {
    let aref: &usize = Box::leak(Box::new(0));
    aref as *const usize as *mut usize
}

fn heap_location() -> u64 {
    static HEAP_LOCATION: std::sync::atomic::AtomicPtr<usize> =
        std::sync::atomic::AtomicPtr::new(0 as *mut usize);
    let mut p = HEAP_LOCATION.load(std::sync::atomic::Ordering::Relaxed) as u64;
    if p == 0 {
        let ptr = allocate_ptr();
        p = match HEAP_LOCATION.compare_exchange(
            std::ptr::null_mut(),
            ptr,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(_) => ptr as u64,
            Err(ptr) => ptr as u64, // this means another thread allocated this.
        };
    }
    p
}

const fn sz<T>() -> u64 {
    std::mem::align_of::<T>() as u64
}

/// The `Fits64` implementation for `Intern<T>` is designed to normally give
/// (relatively) small numbers, by XORing with a fixed pointer that is also on
/// the heap.  The pointer is also divided by its alignment to eliminate those
/// redundant insignificant zeros.  This should make the most significant bits
/// of the resulting u64 be zero, which will mean that `Set64` (which is
/// space-efficient in storing small integers) can store this result in far
/// fewer than 8 bytes.
impl<T> Fits64 for Intern<T> {
    unsafe fn from_u64(x: u64) -> Self {
        Intern {
            pointer: &*(((x ^ heap_location() / sz::<T>()) * sz::<T>()) as *const T),
        }
    }
    fn to_u64(self) -> u64 {
        self.get_pointer() as u64 / sz::<T>() ^ heap_location() / sz::<T>()
    }
}

#[test]
fn test_intern_set64() {
    assert_eq!(1, sz::<u8>());
    assert_eq!(4, sz::<u32>());
    use tinyset::Set64;
    let mut s = Set64::<Intern<u32>>::new();
    s.insert(Intern::new(5));
    s.insert(Intern::new(6));
    s.insert(Intern::new(6));
    s.insert(Intern::new(7));
    assert!(s.contains(Intern::new(5)));
    assert!(s.contains(Intern::new(6)));
    assert!(s.contains(Intern::new(7)));
    assert!(!s.contains(Intern::new(8)));
    for x in s.iter() {
        assert!([5, 6, 7, 8].contains(&x));
    }
    assert_eq!(s.len(), 3);
}

impl<T> AsRef<T> for Intern<T> {
    fn as_ref(&self) -> &T {
        self.pointer
    }
}

impl<T: Eq + Hash + Send + Sync> Deref for Intern<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.as_ref()
    }
}

impl<T: Eq + Hash + Send + Sync + Display> Display for Intern<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        self.deref().fmt(f)
    }
}

impl<T: Eq + Hash + Send + Sync> Pointer for Intern<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        Pointer::fmt(&self.get_pointer(), f)
    }
}

/// The hash implementation returns the hash of the pointer
/// value, not the hash of the value pointed to.  This should
/// be irrelevant, since there is a unique pointer for every
/// value, but it *is* observable, since you could compare the
/// hash of the pointer with hash of the data itself.
impl<T: Eq + Hash + Send + Sync> Hash for Intern<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_pointer().hash(state);
    }
}

impl<T: Eq + Hash + Send + Sync> PartialEq for Intern<T> {
    fn eq(&self, other: &Self) -> bool {
        self.get_pointer() == other.get_pointer()
    }
}

impl<T: Eq + Hash + Send + Sync> Eq for Intern<T> {}

impl<T: Eq + Hash + Send + Sync + PartialOrd> PartialOrd for Intern<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.as_ref().partial_cmp(other)
    }
    fn lt(&self, other: &Self) -> bool {
        self.as_ref().lt(other)
    }
    fn le(&self, other: &Self) -> bool {
        self.as_ref().le(other)
    }
    fn gt(&self, other: &Self) -> bool {
        self.as_ref().gt(other)
    }
    fn ge(&self, other: &Self) -> bool {
        self.as_ref().ge(other)
    }
}

impl<T: Eq + Hash + Send + Sync + Ord> Ord for Intern<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_ref().cmp(other)
    }
}

impl<T: Eq + Hash + Send + Sync + 'static> From<T> for Intern<T> {
    fn from(t: T) -> Self {
        Intern::new(t)
    }
}

impl<T: Eq + Hash + Send + Sync + Default + 'static> Default for Intern<T> {
    fn default() -> Self {
        Intern::new(Default::default())
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[cfg(feature = "serde")]
impl<'de, T: Eq + Hash + Send + Sync + 'static + Deserialize<'de>> Deserialize<'de> for Intern<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(|x: T| Self::new(x))
    }
}
