extern crate macho;

use std::env;
use std::fs;
use std::io::Read;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <file>", args[0]);
        return;
    }

    let mut fh = fs::File::open(&args[1]).unwrap();
    let mut buf: Vec<u8> = Vec::new();
    let _ = fh.read_to_end(&mut buf);

    match macho::MachObject::parse(&buf[..]) {
        Ok(header) => {
            println!("{:#?}", header);
        },
        Err(_) => {
            panic!("Error parsing header")
        }

    }
}
