extern crate eventual;
extern crate libc;
extern crate mio;
extern crate threadpool;

#[cfg(test)] extern crate tempdir;

pub mod linux;

use std::fs::{File, OpenOptions};
use std::io::{Error};

use threadpool::ThreadPool;
use mio::{
    EventLoop,
};

struct Handler;

impl mio::Handler for Handler {
    type Timeout = ();
    type Message = ();
}

use eventual::{
    Async,
    Future,
};

pub struct Reactor {
    event_loop: EventLoop<Handler>,
    threadpool: ThreadPool,
}

impl Reactor {
    fn new() -> Reactor {
        Reactor {
            event_loop: EventLoop::new()
        }
    }
    fn open_file(options: OpenOptions) -> Future<File, Error> {
        unimplemented!()
    }
}
