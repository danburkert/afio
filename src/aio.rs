//! Bindings for the libaio Linux library.

#![allow(non_camel_case_types)]

use std::os::unix::io::AsRawFd;
use std::ptr;

use libc::{
    c_int,
    c_long,
    c_ulong,
    timespec,
};

pub type aio_context_t = c_ulong;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum iocb_cmd {
    PREAD = 0,
    PWRITE = 1,
    PREADV = 7,
    PWRITEV = 8,
}

impl Default for iocb_cmd {
    fn default() -> iocb_cmd { iocb_cmd::PREAD }
}

pub const IOCB_FLAG_RESFD: u32 = 1 << 0;

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct io_event {
    pub data: u64,
    pub obj: u64,
    pub res: i64,
    pub res2: i64,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct iocb {
    pub aio_data: u64,

    #[cfg(target_endian = "big")]
    aio_reserved1: u32,
    aio_key: u32,
    #[cfg(target_endian = "little")]
    aio_reserved1: u32,

    pub aio_lio_opcode: iocb_cmd,
    pub aio_reqprio: i16,
    pub aio_fildes: u32,

    pub aio_buf: u64,
    pub aio_nbytes: u64,
    pub aio_offset: i64,
    aio_reserved2: u64,
    pub aio_flags: u32,
    /// If the IOCB_FLAG_RSFD value in `aio_flags` is set, this is an eventfd to
    /// signal AIO readiness to.
    pub aio_resfd: u32,
}

impl iocb {

    pub fn pread<F>(file: &F, offset: i64, buf: &mut [u8]) -> iocb where F: AsRawFd {
        iocb(iocb_cmd::PREAD, file, offset, buf)
    }

    pub fn pwrite<F>(file: &F, offset: i64, buf: &[u8]) -> iocb where F: AsRawFd {
        iocb(iocb_cmd::PWRITE, file, offset, buf)
    }

    pub fn preadv<F>(file: &F, offset: i64, bufs: &[&mut[u8]], len: usize) -> iocb where F: AsRawFd {
        // This relies on iovec and std::raw::Slice having the same representation.
        iocb(iocb_cmd::PREADV, file, offset, bufs)
    }

    pub fn pwritev<F>(file: &F, offset: i64, bufs: &[&[u8]], len: usize) -> iocb where F: AsRawFd {
        // This relies on iovec and std::raw::Slice having the same representation.
        iocb(iocb_cmd::PWRITEV, file, offset, bufs)
    }

    pub fn set_data(&mut self, data: u64) {
        self.aio_data = data;
    }

    pub fn set_resfd(&mut self, fd: u32) {
        self.aio_resfd = fd;
        self.aio_flags = IOCB_FLAG_RESFD;
    }
}

fn iocb<F, T>(cmd: iocb_cmd, file: &F, offset: i64, buf: &[T]) -> iocb where F: AsRawFd {
    let mut cb = iocb::default();
    cb.aio_fildes = file.as_raw_fd() as u32;
    cb.aio_lio_opcode = cmd;
    cb.aio_reqprio = 0;
    cb.aio_buf = buf.as_ptr() as u64;
    cb.aio_nbytes = buf.len() as u64;
    cb.aio_offset = offset;
    cb
}

#[link(name = "aio")]
extern "C" {
    pub fn io_setup(max_events: c_int, ctx: *mut aio_context_t) -> c_int;
    pub fn io_destroy(ctx: aio_context_t) -> c_int;
    pub fn io_submit(ctx: aio_context_t, nr: c_long, ios: *mut *mut iocb) -> c_int;
    pub fn io_cancel(ctx: aio_context_t, iocb: *mut iocb, event: *mut io_event) -> c_int;
    pub fn io_getevents(ctx: aio_context_t,
                        min_nr: c_long,
                        nr: c_long,
                        events: *mut io_event,
                        timeout: *mut timespec) -> c_int;
}

#[cfg(test)]
mod test {

    use super::*;

    use libc::{
        c_long,
        time_t,
        timespec,
    };
    use std::fs::OpenOptions;
    use std::io::{Error, Result};
    use std::time::Duration;
    use std::ptr;

    use tempdir;

    pub unsafe fn submit(ctx: aio_context_t, ios: &mut [*mut iocb]) -> Result<usize> {
        let ret = io_submit(ctx, ios.len() as c_long, ios.as_mut_ptr());
        if ret < 0 {
            Err(Error::from_raw_os_error(-ret))
        } else {
            Ok(ret as usize)
        }
    }

    pub unsafe fn getevents(ctx: aio_context_t,
                            minimum: usize,
                            events: &mut [io_event],
                            timeout: Option<Duration>) -> Result<usize> {
        let mut timespec = timeout.map(|duration| timespec { tv_sec: duration.as_secs() as time_t,
                                                             tv_nsec: duration.subsec_nanos() as c_long });
        let timeout_ptr = timespec.as_mut().map(|ptr| ptr as *mut _).unwrap_or(ptr::null_mut());

        let ret = io_getevents(ctx,
                               minimum as c_long,
                               events.len() as c_long,
                               events.as_mut_ptr(),
                               timeout_ptr);
        if ret < 0 {
            Err(Error::from_raw_os_error(-ret))
        } else {
            Ok(ret as usize)
        }
    }

    /// Translation of
    /// [Linux Asynchronous I/O Explained](https://www.fsl.cs.sunysb.edu/~vass/linux-aio.txt)
    /// program 1.
    #[test]
    fn program_1() {
        let mut ctx: aio_context_t = 0;
        unsafe {
            assert_eq!(0, io_setup(128, &mut ctx));
            assert_eq!(0, io_destroy(ctx));
        }
    }

    /// Translation of
    /// [Linux Asynchronous I/O Explained](https://www.fsl.cs.sunysb.edu/~vass/linux-aio.txt)
    /// program 2.
    #[test]
    fn program_2() {
        let tempdir = tempdir::TempDir::new("aio").unwrap();
        let mut file = OpenOptions::new()
                                   .create(true)
                                   .read(true)
                                   .write(true)
                                   .open(tempdir.path().join("testfile"))
                                   .unwrap();
        let mut ctx: aio_context_t = 0;

        unsafe {
            assert_eq!(0, io_setup(128, &mut ctx));

            let buf = [42; 4096];
            let mut cb = iocb::pwrite(&mut file, 0, &buf[..]);
            cb.set_data(99);
            let mut cbs: &mut [*mut _] = &mut [&mut cb];

            assert_eq!(1, submit(ctx, cbs).unwrap());

            let events = &mut [io_event::default()];

            assert_eq!(1, getevents(ctx, 1, events, None).unwrap());
            assert_eq!(99, events[0].data);
            assert_eq!(0, io_destroy(ctx));
        }

        ::std::mem::forget(tempdir);
    }
}
