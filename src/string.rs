// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use core::fmt;
use core::mem::MaybeUninit;

use crate::error::SvsmError;

#[derive(Copy, Clone, Debug)]
pub struct FixedString<const T: usize> {
    len: usize,
    data: [u8; T],
}

impl<const T: usize> FixedString<T> {
    pub const fn new() -> Self {
        FixedString {
            len: 0,
            data: [0; T],
        }
    }

    pub fn push(&mut self, c: u8) {
        let l = self.len;

        if l > 0 && self.data[l - 1] == '\0' as u8 {
            return;
        }

        self.data[l] = c;
        self.len += 1;
    }

    pub fn length(&self) -> usize {
        self.len
    }

    pub fn append(&mut self, other: &FixedString<T>) -> Result<(), SvsmError> {
        let mut l = self.len;
        if l > 0 && self.data[l - 1] == '\0' as u8 {
            l = l - 1;
        }
        if (l + other.len) > T {
            return Err(SvsmError::String);
        }
        for i in 0..other.len {
            self.data[l + i] = other.data[i];
        }
        self.len = l + other.len;
        Ok(())
    }

    pub fn as_str(&self) -> &str {
        match core::str::from_utf8(&self.data) {
            Ok(s) => s.trim_end_matches(|x| x == '\0'),
            Err(_) => panic!("FixedString contains invalid UTF-8 data"),
        }
    }
}

impl<const N: usize> From<[u8; N]> for FixedString<N> {
    fn from(arr: [u8; N]) -> FixedString<N> {
        let mut data = MaybeUninit::<u8>::uninit_array::<N>();
        let mut len = N;

        for (i, (d, val)) in data.iter_mut().zip(&arr).enumerate() {
            let val = *val;
            if val == 0 && len == N {
                len = i;
            }
            d.write(val);
        }

        let data = unsafe { MaybeUninit::array_assume_init(data) };
        FixedString { data, len }
    }
}

impl<const N: usize> From<&str> for FixedString<N> {
    fn from(st: &str) -> FixedString<N> {
        let mut fs = FixedString::new();
        for c in st.bytes().take(N) {
            fs.data[fs.len] = c;
            fs.len += 1;
        }
        fs
    }
}

impl<const N: usize> PartialEq<&str> for FixedString<N> {
    fn eq(&self, other: &&str) -> bool {
        for (i, c) in other.bytes().enumerate() {
            if i >= N {
                return false;
            }
            if self.data[i] != c {
                return false;
            }
        }
        true
    }
}

impl<const N: usize> PartialEq<FixedString<N>> for FixedString<N> {
    fn eq(&self, other: &FixedString<N>) -> bool {
        if self.len != other.len {
            return false;
        }

        self.data
            .iter()
            .zip(&other.data)
            .take(self.len)
            .all(|(a, b)| *a == *b)
    }
}

impl<const T: usize> fmt::Display for FixedString<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::FixedString;

    #[test]
    fn new_is_empty() {
        let fs = FixedString::<32>::new();
        assert_eq!(fs.length(), 0);
    }

    #[test]
    fn push_bytes() {
        let mut fs = FixedString::<32>::new();
        fs.push('a' as u8);
        fs.push('b' as u8);
        fs.push('c' as u8);
        assert_eq!(fs.length(), 3);
        assert_eq!(fs, "abc");
    }

    #[test]
    fn from_ascii_str() {
        let ascii = " !\"£$%^*() some ASCII text";
        let fs = FixedString::<40>::from(ascii);
        assert_eq!(fs, ascii);
        assert_eq!(fs.as_str(), ascii);
    }

    #[test]
    fn from_utf8_str() {
        let utf8 = "Ḽơᶉëᶆ ȋṕšᶙṁ ḍỡḽǭᵳ";
        let fs = FixedString::<100>::from(utf8);
        assert_eq!(fs, utf8);
        assert_eq!(fs.as_str(), utf8);
        assert_eq!(fs.length(), utf8.len());
        assert_eq!(fs.as_str().chars().count(), utf8.chars().count());
    }

    #[test]
    fn append_strings() {
        let mut fs1 = FixedString::<100>::from("First string");
        let fs2 = FixedString::<100>::from(", second string");
        assert!(fs1.append(&fs2).is_ok());
        assert_eq!(fs1, "First string, second string");
        assert_eq!(fs1.length(), 27);
    }

    #[test]
    fn append_strings_overflow() {
        let mut fs1 = FixedString::<20>::from("First string");
        let fs2 = FixedString::<20>::from(", second string");
        assert!(fs1.append(&fs2).is_err());
    }

    #[test]
    fn append_zero_terminated() {
        let mut fs1 = FixedString::<100>::from("First string");
        fs1.push(0);
        let fs2 = FixedString::<100>::from(", second string");
        assert!(fs1.append(&fs2).is_ok());
        assert_eq!(fs1, "First string, second string");
        assert_eq!(fs1.length(), 27);
    }
}
