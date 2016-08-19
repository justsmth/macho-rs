#[macro_use]
extern crate nom;
extern crate uuid;
use std::ffi::CStr;
use std::os::raw::c_char;

use nom::{le_u64,le_u32,le_i32};
use nom::IResult;

pub use constants::*;

mod constants;

// These are all integer_t, aka int
#[allow(non_camel_case_types)]
pub type cpu_type_t = i32;
#[allow(non_camel_case_types)]
pub type cpu_subtype_t = u32;
#[allow(non_camel_case_types)]
pub type vm_prot_t = i32;

fn to_string(buf: &[u8]) -> String {
    let slice = unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) };
    std::str::from_utf8(slice.to_bytes()).unwrap().to_string()
}

#[derive(Debug)]
pub struct MachHeader<'a> {
    pub header: Header,
    pub uuid: Option<uuid::Uuid>,
    pub segments: Vec<SegmentCommand>,
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
            let mut uuid = None;
            let mut commands = vec![];
            let mut segments = vec![];
            for _ in 0.. header.ncmds {
                // Thanks to nom being zero copy, we can actually parse the same memory twice.
                // We have one attempt to see what type it is, then we have another go to get that
                // object.
                if let IResult::Done(_, cmd) = load_command(rest) {
                    let len = cmd.cmdsize;
                    match cmd.cmd {
                        c if c == LcType::LC_SEGMENT_64 as u32 => {
                            if let IResult::Done(_rest, mut segment) = segment_command(rest) {
                                let sections_slice = &_rest[.. (segment.cmdsize - 72) as usize];
                                if let IResult::Done(leftover, sections) = sections(sections_slice) {
                                    assert_eq!(sections.len(), segment.nsects as usize);
                                    assert_eq!(leftover.len(), 0);
                                    segment.sections.extend(sections)
                                } else {
                                    return None
                                }
                                segments.push(segment);
                            } else {
                                return None
                            }
                        },
                        c if c == LcType::LC_UUID as u32 => {
                            if let Ok(_uuid) = uuid::Uuid::from_bytes(cmd.data) {
                                uuid = Some(_uuid);
                            }
                        },
                        _ => {
                            commands.push(cmd)
                        }
                    }
                    rest = &rest[len as usize..];
                }
            }

            Some(MachHeader {
                    header: header,
                    uuid: uuid,
                    commands: commands,
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
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: vm_prot_t,
    pub initprot: vm_prot_t,
    pub nsects: u32,
    pub flags: u32,
    pub sections: Vec<Section>,
}

#[derive(Debug)]
pub struct LoadCommand<'a> {
    pub cmd: u32,
    pub cmdsize: u32,
    pub data: &'a [u8],
}

#[derive(Debug)]
pub struct Section {
	pub sectname: String, /* name of this section */
    pub segname: String, /* segment this section goes in */
    pub addr: u64, /* memory address of this section */
    pub size: u64, /* size in bytes of this section */
    pub offset: u32, /* file offset of this section */
    pub align: u32, /* section alignment (power of 2) */
    pub reloff: u32, /* file offset of relocation entries */
    pub nreloc: u32, /* number of relocation entries */
    pub flags: u32, /* flags (section type and attributes)*/
    reserved1: u32, /* reserved (for offset or index) */
    reserved2: u32, /* reserved (for count or sizeof) */
    reserved3: u32, /* reserved */
}

named!(sections<&[u8], Vec<Section> >,
       many0!(section));
named!(section<&[u8], Section>,
       chain!(
           sectname: take!(16) ~
           segname: take!(16) ~
           addr: le_u64 ~
           size: le_u64 ~
           offset: le_u32 ~
           align: le_u32 ~
           reloff: le_u32 ~
           nreloc: le_u32 ~
           flags: le_u32 ~
           reserved1: le_u32 ~
           reserved2: le_u32 ~
           reserved3: le_u32 ,

           || {
               // assert_eq!(size, 80);
               Section {
                   sectname: to_string(sectname),
                   segname: to_string(segname),
                   addr: addr,
                   size: size,
                   offset: offset,
                   align: align,
                   reloff: reloff,
                   nreloc: nreloc,
                   flags: flags,
                   reserved1: reserved1,
                   reserved2: reserved2,
                   reserved3: reserved3,
               }
           }
           )
       );

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
               assert_eq!(MH_MAGIC_64, magic);
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
           flags: le_u32 ,

           || {
               SegmentCommand {
                   cmd: cmd,
                   cmdsize: cmdsize,
                   segname: to_string(segname),
                   vmaddr: vmaddr,
                   vmsize: vmsize,
                   fileoff: fileoff,
                   filesize: filesize,
                   maxprot: maxprot,
                   initprot: initprot,
                   nsects: nsects,
                   flags: flags,
                   sections: vec![],
               }
           }
        )
    );

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parses_lol() {
        let binary = include_bytes!("../test/lol");
        let header = MachHeader::parse(binary).unwrap();
        assert_eq!(header.header.ncmds, 14);
    }

    #[test]
    fn test_parses_uuid() {
        let binary = include_bytes!("../test/dwarfdump");
        let header = MachHeader::parse(binary).unwrap();

        let expected = "1b1a1ba2-c94d-3dc9-b55c-97a296ff0a35";
        let uuid = format!("{}", header.uuid.unwrap());

        assert_eq!(expected, uuid);
    }
}
