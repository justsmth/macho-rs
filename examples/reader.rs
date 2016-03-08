#[macro_use]
extern crate nom;
extern crate macho;

use std::env;
use std::fs;
use std::io::Read;
use nom::IResult;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <file>", args[0]);
        return;
    }

    let mut fh = fs::File::open(&args[1]).unwrap();
    let mut buf: Vec<u8> = Vec::new();
    let _ = fh.read_to_end(&mut buf);

    match macho::MachHeader::parse(&buf[..]) {
        Some(header) => {
            for i in header.segments {
                println!("Segment: {}", i.segname);
            }
        },
        None => {
            panic!("Error parsing header")
        }

    }
}
