#[macro_use]
extern crate nom;
use std::ffi::CStr;
use std::os::raw::c_char;

use nom::{le_u64,le_u32};
use nom::IResult;

#[allow(non_camel_case_types)]
pub type cpu_type_t = usize;
#[allow(non_camel_case_types)]
pub type cpu_subtype_t = usize;
#[allow(non_camel_case_types)]
pub type vm_prot_t = usize;

#[derive(Debug)]
pub struct MachHeader {
    pub header: MachHeader_,
    pub segments: Vec<SegmentCommand>,
}

#[derive(Debug)]
pub struct MachHeader_ {
    pub magic: u32,
    pub cputype: cpu_type_t,
    pub cpusubtype: cpu_subtype_t,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
}

impl MachHeader {
    pub fn parse(bytes: &[u8]) -> Option<MachHeader> {
        if let IResult::Done(_rest, header) = mach_header(bytes) {
            let mut rest = _rest;
            let mut segments = vec![];
            for _ in [0.. header.ncmds].iter() {
                if let IResult::Done(_rest, cmd) = segment_command(rest) {
                    rest = _rest;
                    segments.push(cmd);
                } else {
                    return None
                }
            }

            Some(MachHeader {
                header: header,
                segments: segments,
            })
        } else {
            return None
        }
    }
}

#[derive(Debug)]
pub struct SegmentCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub segname: String,
    pub vmaddr: u32,
    pub vmsize: u32,
    pub fileoff: u32,
    pub filesize: u32,
    pub maxprot: vm_prot_t,
    pub initprot: vm_prot_t,
    pub nsects: u32,
    pub flags: u32,
}

named!(mach_header<&[u8], MachHeader_>,
       chain!(
           magic: le_u32 ~
           // TODO this is presumably broken on 32bit
           cputype: le_u64 ~
           cpusubtype: le_u64 ~
           filetype: le_u32 ~
           ncmds: le_u32 ~
           sizeofcmds: le_u32 ~
           flags: le_u32 ,

           || {
               MachHeader_ {
                   magic: magic,
                   cputype: cputype as usize,
                   cpusubtype: cpusubtype as usize,
                   filetype: filetype,
                   ncmds: ncmds,
                   sizeofcmds: sizeofcmds,
                   flags: flags,
               }
           }
           )
       );

named!(segment_command<&[u8], SegmentCommand>,
       chain!(
           cmd: le_u32 ~
           cmdsize: le_u32 ~
           segname: take!(16) ~
           vmaddr: le_u32 ~
           vmsize: le_u32 ~
           fileoff: le_u32 ~
           filesize: le_u32 ~
           maxprot: le_u64 ~
           initprot: le_u64 ~
           nsects: le_u32 ~
           flags: le_u32 ,

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
                   maxprot: maxprot as usize,
                   initprot: initprot as usize,
                   nsects: nsects,
                   flags: flags,
               }
           }
        )
    );


