#[macro_use]
extern crate nom;
use std::ffi::CStr;
use std::os::raw::c_char;

use nom::{le_u64,le_u32,le_i32};
use nom::IResult;

// These are all integer_t, aka int
#[allow(non_camel_case_types)]
pub type cpu_type_t = i32;
#[allow(non_camel_case_types)]
pub type cpu_subtype_t = u32;
#[allow(non_camel_case_types)]
pub type vm_prot_t = i32;

#[derive(Debug)]
pub struct MachHeader<'a> {
    pub header: Header,
    pub segments: Vec<SegmentCommand<'a>>,
    pub commands: Vec<LoadCommand<'a>>,
}

#[derive(Debug)]
pub struct Header {
    pub magic: u32,
    pub cputype: cpu_type_t,
    pub cpusubtype: cpu_subtype_t,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    reserved: u32,
}

pub const LC_SEGMENT_64: u32 = 25;

impl<'a> MachHeader<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<MachHeader> {
        if let IResult::Done(_rest, header) = mach_header(bytes) {
            let mut rest = _rest;
            let mut commands = vec![];
            let mut segments = vec![];
            for _ in 0.. header.ncmds {
                // Thanks to nom being zero copy, we can actually parse the same memory twice.
                // We have one attempt to see what type it is, then we have another go to get that
                // object.
                if let IResult::Done(_, cmd) = load_command(rest) {
                    match cmd.cmd {
                        LC_SEGMENT_64 => {
                            if let IResult::Done(_rest, segment) = segment_command(rest) {
                                rest = _rest;
                                segments.push(segment);
                            } else {
                                return None
                            }
                        },
                        _ => {
                            commands.push(cmd)
                        }
                    }
                }
            }

            Some(MachHeader {
                    header: header,
                    commands: commands,
                    segments: segments,
            })
        } else {
            return None
        }
    }
}

#[derive(Debug)]
pub struct SegmentCommand<'a> {
    pub cmd: u32,
    pub cmdsize: u32,
    pub segname: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: vm_prot_t,
    pub initprot: vm_prot_t,
    pub nsects: u32,
    pub flags: u32,
    pub data: &'a [u8],
}

#[derive(Debug)]
pub struct LoadCommand<'a> {
    pub cmd: u32,
    pub cmdsize: u32,
    pub data: &'a [u8],
}

named!(load_command<&[u8], LoadCommand>,
       chain!(
           cmd: le_u32 ~
           cmdsize: le_u32 ~
           data: take!(cmdsize - 8),

           || {
               LoadCommand {
                   cmd: cmd,
                   cmdsize: cmdsize,
                   data: data,
               }
           }
           )
       );

named!(mach_header<&[u8], Header>,
       chain!(
           magic: le_u32 ~
           cputype: le_i32 ~
           cpusubtype: le_u32 ~
           filetype: le_u32 ~
           ncmds: le_u32 ~
           sizeofcmds: le_u32 ~
           flags: le_u32 ~
           reserved: le_u32,


           || {
               assert_eq!(0xfeedfacf, magic);
               Header {
                   magic: magic,
                   cputype: cputype,
                   // This value needs to be masked to match otool -h
                   cpusubtype: cpusubtype,
                   filetype: filetype,
                   ncmds: ncmds,
                   sizeofcmds: sizeofcmds,
                   flags: flags,
                   reserved: reserved,
               }
           }
           )
       );

named!(segment_command<&[u8], SegmentCommand>,
       chain!(
           cmd: le_u32 ~
           cmdsize: le_u32 ~
           segname: take!(16) ~
           vmaddr: le_u64 ~
           vmsize: le_u64 ~
           fileoff: le_u64 ~
           filesize: le_u64 ~
           maxprot: le_i32 ~
           initprot: le_i32 ~
           nsects: le_u32 ~
           flags: le_u32 ~
           data: take!(cmdsize - 72) ,


           || {

               let slice = unsafe { CStr::from_ptr(segname.as_ptr() as *const c_char) };
               let name = std::str::from_utf8(slice.to_bytes()).unwrap().to_string();

               SegmentCommand {
                   cmd: cmd,
                   cmdsize: cmdsize,
                   segname: name,
                   vmaddr: vmaddr,
                   vmsize: vmsize,
                   fileoff: fileoff,
                   filesize: filesize,
                   maxprot: maxprot,
                   initprot: initprot,
                   nsects: nsects,
                   flags: flags,
                   data: data,
               }
           }
        )
    );


