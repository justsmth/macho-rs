#[macro_use]
extern crate nom;
extern crate uuid;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

use nom::IResult;
use nom::{le_i16, le_i32, le_u32, le_u64, le_u8};

pub use crate::constants::*;

mod constants;

// These are all integer_t, aka int
#[allow(non_camel_case_types)]
pub type cpu_type_t = c_int;
#[allow(non_camel_case_types)]
pub type cpu_subtype_t = c_int;
#[allow(non_camel_case_types)]
pub type vm_prot_t = c_int;

fn to_string(buf: &[u8]) -> String {
    let slice = unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) };
    std::str::from_utf8(slice.to_bytes()).unwrap().to_string()
}

#[derive(Debug)]
pub struct MachObject<'a> {
    pub header: Header,
    pub uuid: Option<uuid::Uuid>,
    pub segments: Vec<SegmentCommand>,
    pub commands: Vec<LoadCommand<'a>>,
    pub symtab: Vec<SymbolTable>,
}

#[allow(dead_code)]
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

fn build_slice(bytes: &[u8], start_offset: usize, size: usize) -> &[u8] {
    let slice_end = start_offset + size;
    &bytes[start_offset..slice_end]
}

impl<'a> MachObject<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<MachObject, ()> {
        if let IResult::Done(_rest, header) = mach_header(bytes) {
            let mut rest = _rest;
            let mut uuid = None;
            let mut commands = vec![];
            let mut segments = vec![];
            let mut symtab = vec![];
            for _ in 0..header.ncmds {
                // Thanks to nom being zero copy, we can actually parse the same memory twice.
                // We have one attempt to see what type it is, then we have another go to get that
                // object.
                if let IResult::Done(_, cmd) = load_command(rest) {
                    let len = cmd.cmdsize;
                    match cmd.cmd {
                        c if c == LcType::LC_SEGMENT_64 as u32 => {
                            if let IResult::Done(_rest, mut segment) = segment_command(rest) {
                                let sections_slice = &_rest[..(segment.cmdsize - 72) as usize];
                                if let IResult::Done(leftover, sections) = sections(sections_slice)
                                {
                                    assert_eq!(sections.len(), segment.nsects as usize);
                                    assert_eq!(leftover.len(), 0);
                                    segment.sections.extend(sections)
                                } else {
                                    return Err(());
                                }
                                segments.push(segment);
                            } else {
                                return Err(());
                            }
                        }
                        c if c == LcType::LC_UUID as u32 => {
                            if let Ok(_uuid) = uuid::Uuid::from_bytes(cmd.data) {
                                uuid = Some(_uuid);
                            }
                        }
                        c if c == LcType::LC_SYMTAB as u32 => {
                            commands.push(cmd);
                            if let IResult::Done(_rest, mut my_symtab) = symtab_command(rest) {
                                let sym_table_slice = build_slice(
                                    bytes,
                                    my_symtab.symoff as usize,
                                    my_symtab.nsyms as usize * 16,
                                );
                                let str_table_slice = build_slice(
                                    bytes,
                                    my_symtab.stroff as usize,
                                    my_symtab.strsize as usize,
                                );

                                if let IResult::Done(leftover, mut symtab_entries) =
                                    symtab_entries(sym_table_slice)
                                {
                                    assert_eq!(my_symtab.nsyms as usize, symtab_entries.len());
                                    assert_eq!(leftover.len(), 0);
                                    for mut entry in symtab_entries.iter_mut() {
                                        let str_offset = entry.n_strx as usize;
                                        let str_slice = &str_table_slice[str_offset..];
                                        if let IResult::Done(_leftover, sym_string) =
                                            sym_string(str_slice)
                                        {
                                            let name =
                                                String::from_utf8(Vec::from(sym_string)).unwrap();
                                            entry.symbol = name;
                                        } else {
                                            return Err(());
                                        }
                                    }
                                    my_symtab.entries = symtab_entries;
                                } else {
                                    return Err(());
                                }
                                symtab.push(my_symtab);
                            } else {
                                return Err(());
                            }
                        }
                        _ => commands.push(cmd),
                    }
                    rest = &rest[len as usize..];
                } else {
                    return Err(());
                }
            }

            Ok(MachObject {
                header,
                uuid,
                commands,
                segments,
                symtab,
            })
        } else {
            Err(())
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

#[allow(dead_code)]
#[derive(Debug)]
pub struct Section {
    pub sectname: String, /* name of this section */
    pub segname: String,  /* segment this section goes in */
    pub addr: u64,        /* memory address of this section */
    pub size: u64,        /* size in bytes of this section */
    pub offset: u32,      /* file offset of this section */
    pub align: u32,       /* section alignment (power of 2) */
    pub reloff: u32,      /* file offset of relocation entries */
    pub nreloc: u32,      /* number of relocation entries */
    pub flags: u32,       /* flags (section type and attributes)*/
    reserved1: u32,       /* reserved (for offset or index) */
    reserved2: u32,       /* reserved (for count or sizeof) */
    reserved3: u32,       /* reserved */
}

#[derive(Debug)]
pub struct SymbolTable {
    pub cmd: u32,
    pub cmdsize: u32,
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
    pub entries: Vec<SymbolTableEntry>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct SymbolTableEntry {
    pub n_strx: i32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: i16,
    pub n_value: u64,
    pub symbol: String,
}

named!(
    sym_string,
    terminated!(take_while!(|b: u8| b != 0), tag!([0]))
);

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
            addr,
            size,
            offset,
            align,
            reloff,
            nreloc,
            flags,
            reserved1,
            reserved2,
            reserved3,
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
            cmd,
            cmdsize,
            data,
        }
    }
    )
);

named!(symtab_command<&[u8], SymbolTable>,
chain!(
    cmd: le_u32 ~
    cmdsize: le_u32 ~
    symoff: le_u32 ~
    nsyms: le_u32 ~
    stroff: le_u32 ~
    strsize: le_u32 ,

    || {
        SymbolTable {
            cmd,
            cmdsize,
            symoff,
            nsyms,
            stroff,
            strsize,
            entries: vec![]
        }
    }
    )
);

named!(symtab_entries<&[u8], Vec<SymbolTableEntry> >,
       many0!(symtab_entry));
named!(symtab_entry<&[u8], SymbolTableEntry>,
chain!(
    n_strx: le_i32 ~
    n_type: le_u8 ~
    n_sect: le_u8 ~
    n_desc: le_i16 ~
    n_value: le_u64,

    || {
        SymbolTableEntry {
            n_strx,
            n_type,
            n_sect,
            n_desc,
            n_value,
            symbol: "".to_string()
        }
    }
    )
);

named!(mach_header<&[u8], Header>,
chain!(
    magic: le_u32 ~
    cputype: le_i32 ~
    cpusubtype: le_i32 ~
    filetype: le_u32 ~
    ncmds: le_u32 ~
    sizeofcmds: le_u32 ~
    flags: le_u32 ~
    reserved: le_u32,


    || {
        assert_eq!(MH_MAGIC_64, magic);
        Header {
            magic,
            cputype,
            // This value needs to be masked to match otool -h
            cpusubtype,
            filetype,
            ncmds,
            sizeofcmds,
            flags,
            reserved,
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
               cmd,
               cmdsize,
               segname: to_string(segname),
               vmaddr,
               vmsize,
               fileoff,
               filesize,
               maxprot,
               initprot,
               nsects,
               flags,
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
        let header = MachObject::parse(binary).unwrap();
        assert_eq!(header.header.ncmds, 14);
    }

    #[test]
    fn test_parses_uuid() {
        let binary = include_bytes!("../test/dwarfdump");
        let header = MachObject::parse(binary).unwrap();

        let expected = "7ab877de-19d1-3a1c-95bf-ff8a0647373a";
        let uuid = format!("{}", header.uuid.unwrap());

        assert_eq!(expected, uuid);
    }

    #[test]
    fn test_parses_symbol_table() {
        let binary = include_bytes!("../test/dwarfdump");
        let header = MachObject::parse(binary).unwrap();

        assert_eq!(1, header.symtab.len());
        assert_eq!(15, header.symtab.get(0).unwrap().entries.len());
        assert_eq!(
            "dyld_stub_binder",
            header
                .symtab
                .get(0)
                .unwrap()
                .entries
                .get(14)
                .unwrap()
                .symbol
        )
    }
}
