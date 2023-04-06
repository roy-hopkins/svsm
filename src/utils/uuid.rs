// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>
//
// vim: ts=4 sw=4 et
use core::fmt;
use core::str::FromStr;

pub struct Uuid {
    data: [u8; 16],
}

fn from_hex(c: char) -> Result<u8, ()> {
    match c.to_digit(16) {
        Some(d) => Ok(d as u8),
        None => Err(()),
    }
}

impl Uuid {
    pub const fn new() -> Self {
        Uuid { data: [0; 16] }
    }

    pub unsafe fn from_mem(ptr: *const u8) -> Self {
        Uuid {
            data: [
                ptr.offset(3).read(),
                ptr.offset(2).read(),
                ptr.offset(1).read(),
                ptr.offset(0).read(),
                ptr.offset(5).read(),
                ptr.offset(4).read(),
                ptr.offset(7).read(),
                ptr.offset(6).read(),
                ptr.offset(8).read(),
                ptr.offset(9).read(),
                ptr.offset(10).read(),
                ptr.offset(11).read(),
                ptr.offset(12).read(),
                ptr.offset(13).read(),
                ptr.offset(14).read(),
                ptr.offset(15).read(),
            ],
        }
    }
}

impl FromStr for Uuid {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut uuid = Uuid::new();
        let mut buf: u8 = 0;
        let mut index = 0;

        for c in s.chars() {
            if !c.is_ascii_hexdigit() {
                continue;
            }

            if (index % 2) == 0 {
                buf = from_hex(c)? << 4;
            } else {
                buf |= from_hex(c)?;
                let i = index / 2;
                if i >= 16 {
                    break;
                }
                uuid.data[i] = buf;
            }

            index += 1;
        }
        
        Ok(uuid)
    }
}

impl PartialEq for Uuid {
    fn eq(&self, other: &Self) -> bool {
        for (a, b) in self.data.iter().zip(&other.data) {
            if a != b {
                return false;
            }
        }
        return true;
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..16 {
            write!(f, "{:02x}", self.data[i])?;
            if i == 3 || i == 5 || i == 7 || i == 9 {
                write!(f, "-")?;
            }
        }
        Ok(())
    }
}
