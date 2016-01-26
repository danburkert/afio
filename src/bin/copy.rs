#![feature(alloc, heap_api, time2)]

extern crate afio;
extern crate fs2;
extern crate libc;
extern crate mio;
extern crate slab;
extern crate alloc;

use std::cmp;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Error, Result};
use std::os::unix::io::{AsRawFd, RawFd};
use std::slice;
use std::u32;
use std::time::{Duration, Instant};
use std::ptr;

use alloc::heap;
use afio::aio;
use fs2::FileExt;
use mio::{EventLoop, PollOpt, Token, EventSet};

const MAX_IO_DEPTH: usize = 32;
const BLOCK_SIZE: u64 = 4096;

#[derive(Debug)]
struct Block(aio::iocb);

impl Block {
    fn read<F>(file: &F, offset: u64, len: usize, eventfd: u32, token: mio::Token) -> Block where F: AsRawFd {
        unsafe {
            let buf = slice::from_raw_parts_mut(heap::allocate(len as usize, BLOCK_SIZE as usize), len);
            let mut iocb = aio::iocb::pread(file, offset as i64, buf);

            iocb.set_resfd(eventfd as u32);
            iocb.set_data(token.as_usize() as u64);

            Block(iocb)
        }
    }

    fn submit(&mut self, context: aio::aio_context_t) -> Result<()> {
        let start = Instant::now();
        let ret = unsafe { aio::io_submit(context, 1, &mut (&mut self.0 as *mut _)) };
        //println!("submit time: {:?}", start.elapsed());
        if ret < 0 {
            Err(Error::from_raw_os_error(-ret))
        } else {
            assert_eq!(1, ret);
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct EventFd(pub libc::c_int);

impl mio::Evented for EventFd {
    fn register(&self,
                selector: &mut mio::Selector,
                token: mio::Token,
                interest: mio::EventSet,
                opts: mio::PollOpt)
                -> Result<()> {
        selector.register(self.0 as RawFd, token, interest, opts)
    }

    fn reregister(&self,
                  selector: &mut mio::Selector,
                  token: mio::Token,
                  interest: mio::EventSet,
                  opts: mio::PollOpt)
                  -> Result<()> {
        selector.reregister(self.0 as RawFd, token, interest, opts)
    }

    fn deregister(&self, selector: &mut mio::Selector) -> Result<()> {
        selector.deregister(self.0 as RawFd)
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        unsafe {
            alloc::heap::deallocate(self.0.aio_buf as *mut _, self.0.aio_nbytes as usize, 4096);
        }
    }
}

struct Copier {
    src: File,
    dst: File,
    src_len: u64,
    /// Tracks the next read offset to initiate.
    offset: u64,
    context: aio::aio_context_t,
    eventfd: u32,
    slab: slab::Slab<Block, mio::Token>
}

impl Copier {
    pub fn copy(src: File, dst: File) -> Result<()> {

        let src_len = try!(src.metadata()).len();
        assert_eq!(0, try!(dst.metadata()).len());
        try!(dst.allocate(src_len));

        let mut ctx: aio::aio_context_t = 0;
        unsafe {
            let res = aio::io_setup(16, &mut ctx);
            if res != 0 {
                return Err(Error::from_raw_os_error(res));
            }
        }

        let eventfd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        assert!(eventfd > 0);

        let mut copier = Copier {
            src: src,
            dst: dst,
            src_len: src_len,
            offset: 0,
            eventfd: eventfd as u32,
            context: ctx,
            slab: slab::Slab::new(MAX_IO_DEPTH),
        };

        let mut event_loop = try!(EventLoop::new());
        event_loop.register(&EventFd(eventfd),
                            Token(0),
                            EventSet::readable() | EventSet::error() | EventSet::hup(),
                            PollOpt::level());
        copier.initiate_block_reads(&mut event_loop);
        event_loop.run(&mut copier).unwrap();
        Ok(())
    }

    fn initiate_block_reads(&mut self, event_loop: &mut EventLoop<Copier>) {
        println!("initiate_block_Reads");
        let Copier { ref src, ref mut offset, src_len, ref mut slab, eventfd, context, .. } = *self;
        println!("offset: {}, src_len: {}, slab.is_empty(): {}", *offset, src_len, slab.is_empty());
        while *offset < src_len && slab.has_remaining() {
            let len = cmp::min(BLOCK_SIZE, src_len - *offset);
            let token = slab.insert_with(|token| Block::read(src, *offset, len as usize, eventfd, token)).unwrap();
            println!("Registering to read at offset: {}, len: {}, token: {:?}, block: {:?}", *offset, len, token, &slab[token]);
            slab[token].submit(context).unwrap();
            *offset += len;
        }
    }
}

impl Drop for Copier {
    fn drop(&mut self) {
        unsafe { libc::close(self.eventfd as libc::c_int) };
    }
}

unsafe fn getevents(ctx: aio::aio_context_t,
                    minimum: usize,
                    events: &mut [aio::io_event],
                    timeout: Option<Duration>) -> Result<usize> {
    let mut timespec = timeout.map(|duration| libc::timespec { tv_sec: duration.as_secs() as libc::time_t,
                                                            tv_nsec: duration.subsec_nanos() as libc::c_long });
    let timeout_ptr = timespec.as_mut().map(|ptr| ptr as *mut _).unwrap_or(ptr::null_mut());

    let ret = aio::io_getevents(ctx,
                            minimum as libc::c_long,
                            events.len() as libc::c_long,
                            events.as_mut_ptr(),
                            timeout_ptr);
    if ret < 0 {
        Err(Error::from_raw_os_error(-ret))
    } else {
        Ok(ret as usize)
    }
}

impl mio::Handler for Copier {
    type Timeout = ();
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<Self>, t: mio::Token, events: mio::EventSet) {

        assert_eq!(t, Token(0));

        let events = &mut [aio::io_event::default()];
        unsafe {
            assert_eq!(getevents(self.context, 1, events, None).unwrap(), 1);
        }

        let token = events[0].data;
        let mut block = self.slab.remove(Token(token as usize)).unwrap();
        println!("done! event: {:?}: {:?}", events[0], block);

        if block.0.aio_lio_opcode == aio::iocb_cmd::PREAD {
            //println!("Reregistering to write at offset: {}, token: {}", block.0.aio_offset, block.0.aio_data);
            block.0.aio_lio_opcode = aio::iocb_cmd::PWRITE;
            block.0.aio_fildes = self.dst.as_raw_fd() as u32;
            let token = self.slab.insert(block).unwrap();
            self.slab[token].0.aio_data = token.as_usize() as u64;
            self.slab[token].submit(self.context).unwrap();
        } else if self.offset < self.src_len {
            block.0.aio_lio_opcode = aio::iocb_cmd::PREAD;
            block.0.aio_fildes = self.src.as_raw_fd() as u32;
            block.0.aio_offset = self.offset as i64;
            let len = cmp::min(BLOCK_SIZE, self.src_len - self.offset);
            block.0.aio_nbytes = len;
            //println!("Reregistering to read at offset: {}, block: {:?}", self.offset, block);
            self.offset += len;
            let token = self.slab.insert(block).unwrap();
            self.slab[token].0.aio_data = token.as_usize() as u64;
            self.slab[token].submit(self.context).unwrap();
        } else {
            if self.slab.is_empty() {
                println!("done!");
                event_loop.shutdown();
            }
        }
    }
}

const USAGE: &'static str = "Usage: copy <src> <dst>";

fn set_nonblocking(file: &File) -> Result<()> {
    unsafe {
        let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
        if flags < 0 {
            return Err(Error::last_os_error());
        }

        let flags = flags | libc::O_DIRECT;
        println!("setting flags to: {}", flags);

        if libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags) < 0 {
            return Err(Error::last_os_error());
        }
        let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
        println!("nonblocking flags: {}", flags);
        Ok(())
    }
}

fn main() {
    let mut args = env::args().skip(2);
    let src = args.next().expect(USAGE);
    let dst = args.next().expect(USAGE);

    let src = OpenOptions::new()
                          .read(true)
                          .write(false)
                          .create(false)
                          .open(src)
                          .unwrap();

    let dst = OpenOptions::new()
                          .read(true)
                          .write(true)
                          .truncate(true)
                          .create(true)
                          .open(dst)
                          .unwrap();

    set_nonblocking(&src).unwrap();
    set_nonblocking(&dst).unwrap();

    Copier::copy(src, dst).unwrap();
}
