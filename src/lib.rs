use nom::bytes::complete::tag;
use nom::bytes::complete::take;
use nom::combinator::opt;
use nom::multi::many0;
use nom::number::complete::le_u16;
use nom::number::complete::le_u32;
use nom::sequence::tuple;
use nom::IResult;
use std::fs::File as FsFile;
use std::io::prelude::*;

pub fn parse(input: &[u8]) -> IResult<&[u8], ZipFile> {
    let (input, (files, central_directory, _)) = tuple((
        many0(parse_local_file),
        // archive parse ?
        parse_central_directory,
        // zip64 parse ?
        parse_end_of_central_directory_record,
    ))(input)?;
    Ok((
        input,
        ZipFile {
            files: files,
            central_directory: central_directory,
        },
    ))
}

/// Describe zip file's part
pub struct ZipFile<'a> {
    /// Files in the zip
    files: Vec<File<'a>>,
    central_directory: CentralDirectory<'a>,
}

pub struct File<'a> {
    /// Header part of file
    header: LocalFileHeader<'a>,
    // encryption_header,
    /// Compressed data of the file
    data: &'a [u8],
    // Data descriptor if present
    data_descsriptor: Option<DataDescriptor>,
}

pub struct CentralDirectory<'a> {
    header: Vec<CentralDirectoryHeader<'a>>,
    signature: Option<DigitalSignature<'a>>,
}

pub struct CentralDirectoryHeader<'a> {
    version_made_by: u16,
    version_needed_to_extract: u16,
    general_purpose_bit_flag: u16, // @TODO represent this
    compression_method: CompressionMethod,
    last_modification_time: u16,
    last_modification_date: u16,
    crc_32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    file_name_length: u16,
    extra_field_length: u16,
    file_comment_length: u16,
    disk_number_start: u16,
    internal_file_attributes: u16,
    external_file_attributes: u32,
    relative_offset_of_local_header: u32,
    file_name: &'a [u8],
    extra_field: &'a [u8],
    file_comment: &'a [u8],
}

pub struct DigitalSignature<'a> {
    size: u16,
    data: &'a [u8],
}

struct DataDescriptor {
    crc_32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
}

// struct GeneralPurposeBitFlag {
//     bit_flag: u16,
// }

#[derive(Debug, PartialEq)]
struct GeneralPurposeBitFlag(u16);

impl GeneralPurposeBitFlag {
    fn has_data_descriptor(&self) -> bool {
        (self.0 & 0b00100000) != 0
    }
}

/// parse file:
///   [local file header 1]
///   [encryption header 1]
///   [file data 1]
///   [data descriptor 1]
fn parse_local_file(input: &[u8]) -> IResult<&[u8], File> {
    let (input, local_file_header) = parse_local_file_header(input)?;
    // parse encryption header ?
    // parse file_data
    let mut data_descsriptor: Option<DataDescriptor> = None;
    let file_size_known = !local_file_header.general_purpose_bit_flag.has_data_descriptor()
        || local_file_header.compressed_size > 0;
    let (input, _compressed_data) = if file_size_known {
        let (input, _compressed_data) = take(local_file_header.compressed_size as usize)(input)?;
        assert!(_compressed_data.len() as u32 == local_file_header.compressed_size);
        (input, _compressed_data)
    } else {
        let (input, _compressed_data) =
            parse_compressed_data(local_file_header.compression_method, input)?;
        let (input, _data_descsriptor) = parse_data_descriptor(input)?;
        assert!(_compressed_data.len() as u32 == _data_descsriptor.compressed_size);
        data_descsriptor = Some(_data_descsriptor);
        (input, _compressed_data)
    };
    Ok((
        input,
        File {
            header: local_file_header,
            data: _compressed_data,
            data_descsriptor: data_descsriptor,
        },
    ))
}

#[derive(Debug, PartialEq)]
pub struct LocalFileHeader<'a> {
    version_needed_to_extract: u16,
    general_purpose_bit_flag: GeneralPurposeBitFlag,
    compression_method: CompressionMethod,
    last_modification_time: u16,
    last_modification_date: u16,
    crc_32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    file_name_length: u16,
    extra_field_length: u16,
    file_name: &'a [u8],
    extra_field: &'a [u8],
}

fn parse_local_file_header(input: &[u8]) -> IResult<&[u8], LocalFileHeader> {
    let (input, _local_file_header_signature) = tag([0x50, 0x4b, 0x03, 0x04])(input)?;
    let (input, minimum_version_needed_to_extract) = le_u16(input)?;
    let (input, general_purpose_bit_flag) = le_u16(input)?;
    let (input, compression_method) = parse_compression_method(input)?;
    let (input, file_last_modification_time) = le_u16(input)?;
    let (input, file_last_modification_date) = le_u16(input)?;
    let (input, crc_32) = le_u32(input)?;
    let (input, compressed_size) = le_u32(input)?;
    let (input, uncompressed_size) = le_u32(input)?;
    let (input, file_name_length) = le_u16(input)?;
    let (input, extra_field_length) = le_u16(input)?;
    let (input, file_name) = take(file_name_length as usize)(input)?;
    let (input, extra_field) = take(extra_field_length as usize)(input)?;

    Ok((
        input,
        LocalFileHeader {
            version_needed_to_extract: minimum_version_needed_to_extract,
            general_purpose_bit_flag: GeneralPurposeBitFlag(general_purpose_bit_flag),
            compression_method: compression_method,
            last_modification_time: file_last_modification_time,
            last_modification_date: file_last_modification_date,
            crc_32: crc_32,
            compressed_size: compressed_size,
            uncompressed_size: uncompressed_size,
            file_name_length: file_name_length,
            extra_field_length: extra_field_length,
            file_name: file_name,
            extra_field: extra_field,
        },
    ))
}

fn parse_compressed_data(
    compression_method: CompressionMethod,
    input: &[u8],
) -> IResult<&[u8], &[u8]> {
    todo!()
}

fn parse_data_descriptor(input: &[u8]) -> IResult<&[u8], DataDescriptor> {
    let (input, _local_file_header_signature) = opt(tag([0x50, 0x4b, 0x07, 0x08]))(input)?;
    let (input, _crc_32) = le_u32(input)?;
    let (input, _compressed_size) = le_u32(input)?;
    let (input, _uncompressed_size) = le_u32(input)?;
    Ok((
        input,
        DataDescriptor {
            crc_32: _crc_32,
            compressed_size: _compressed_size,
            uncompressed_size: _uncompressed_size,
        },
    ))
}

fn parse_central_directory(input: &[u8]) -> IResult<&[u8], CentralDirectory> {
    let (input, central_directory_headers) = many0(parse_central_directory_file_header)(input)?;
    let (input, signature) = opt(parse_central_directory_signature)(input)?;
    Ok((
        input,
        CentralDirectory {
            header: central_directory_headers,
            signature: signature,
        },
    ))
}

fn parse_central_directory_file_header(input: &[u8]) -> IResult<&[u8], CentralDirectoryHeader> {
    let (input, _local_file_header_signature) = tag([0x50, 0x4b, 0x01, 0x02])(input)?;
    let (input, version_made_by) = le_u16(input)?;
    let (input, minimum_version_needed_to_extract) = le_u16(input)?;
    let (input, general_purpose_bit_flag) = le_u16(input)?;
    let (input, compression_method) = parse_compression_method(input)?;
    let (input, file_last_modification_time) = le_u16(input)?;
    let (input, file_last_modification_date) = le_u16(input)?;
    let (input, crc_32) = le_u32(input)?;
    let (input, compressed_size) = le_u32(input)?;
    let (input, uncompressed_size) = le_u32(input)?;
    let (input, file_name_length) = le_u16(input)?;
    let (input, extra_field_length) = le_u16(input)?;
    let (input, file_comment_length) = le_u16(input)?;
    let (input, disk_number_where_file_starts) = le_u16(input)?;
    let (input, internal_file_attributes) = le_u16(input)?;
    let (input, external_file_attributes) = le_u32(input)?;
    let (input, relative_offset_of_local_file_header) = le_u32(input)?;
    let (input, file_name) = take(file_name_length as usize)(input)?;
    let (input, extra_field) = take(extra_field_length as usize)(input)?;
    let (input, file_comment) = take(file_comment_length as usize)(input)?;
    Ok((
        input,
        CentralDirectoryHeader {
            version_made_by: version_made_by,
            version_needed_to_extract: minimum_version_needed_to_extract,
            general_purpose_bit_flag: general_purpose_bit_flag, // @TODO how to store ?
            compression_method: compression_method,
            last_modification_time: file_last_modification_time,
            last_modification_date: file_last_modification_date,
            crc_32: crc_32,
            compressed_size: compressed_size,
            uncompressed_size: uncompressed_size,
            file_name_length: file_name_length,
            extra_field_length: extra_field_length,
            file_comment_length: file_comment_length,
            disk_number_start: disk_number_where_file_starts,
            internal_file_attributes: internal_file_attributes,
            external_file_attributes: external_file_attributes,
            relative_offset_of_local_header: relative_offset_of_local_file_header,
            file_name: file_name,
            extra_field: extra_field,
            file_comment: file_comment,
        },
    ))
}

fn parse_central_directory_signature(input: &[u8]) -> IResult<&[u8], DigitalSignature> {
    let (input, _central_directory_signature) = tag([0x50, 0x4b, 0x05, 0x05])(input)?;
    let (input, size) = le_u16(input)?;
    let (input, data) = take(size as usize)(input)?;
    Ok((
        input,
        DigitalSignature {
            size: size,
            data: data,
        },
    ))
}

pub struct EndOfCentralDirectory<'a> {
    number_of_this_disk: u16,
    disk_where_central_directory_starts: u16,
    number_of_central_directory_records_on_this_disk: u16,
    total_number_of_central_directory_records: u16,
    size_of_central_directory: u32,
    offset_of_start_of_central_directory_relative_to_start_of_archive: u32,
    comment_length: u16,
    comment: &'a [u8],
}

fn parse_end_of_central_directory_record(input: &[u8]) -> IResult<&[u8], EndOfCentralDirectory> {
    let (input, _end_of_central_directory_signature) = tag([0x50, 0x4b, 0x05, 0x06])(input)?;
    let (input, number_of_this_disk) = le_u16(input)?;
    let (input, disk_where_central_directory_starts) = le_u16(input)?;
    let (input, number_of_central_directory_records_on_this_disk) = le_u16(input)?;
    let (input, total_number_of_central_directory_records) = le_u16(input)?;
    let (input, size_of_central_directory) = le_u32(input)?;
    let (input, offset_of_start_of_central_directory_relative_to_start_of_archive) = le_u32(input)?;
    let (input, comment_length) = le_u16(input)?;
    let (input, comment) = take(comment_length as usize)(input)?;
    Ok((
        input,
        EndOfCentralDirectory {
            number_of_this_disk: number_of_this_disk,
            disk_where_central_directory_starts: disk_where_central_directory_starts,
            number_of_central_directory_records_on_this_disk:
                number_of_central_directory_records_on_this_disk,
            total_number_of_central_directory_records: total_number_of_central_directory_records,
            size_of_central_directory: size_of_central_directory,
            offset_of_start_of_central_directory_relative_to_start_of_archive:
                offset_of_start_of_central_directory_relative_to_start_of_archive,
            comment_length: comment_length,
            comment: comment,
        },
    ))
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CompressionMethod {
    FileStored,
    FileShrunk,
    FileReducedCompression1,
    FileReducedCompression2,
    FileReducedCompression3,
    FileReducedCompression4,
    FileImploded,
    ReservedTokenizingCompressionAlgorithm,
    FileDeflated,
    FileDeflated64,
    PKWAREDataCompressionLirarImploding,
    PKWAREReserved11,
    FileCompressedBZIP2,
    PKWAREReserved13,
    LZMA,
    PKWAREReserved15,
    IBMCMPSCCompression,
    PKWAREReserved17,
    FileCompressedIBMTERSE,
    IBMLZ77,
    JPEGVariant,
    WavPack,
    PPMdV1R1,
    EncryptionMarker,
}

fn parse_compression_method(input: &[u8]) -> IResult<&[u8], CompressionMethod> {
    let (input, compression_method_bytes) = le_u16(input)?;
    let compression_method = match compression_method_bytes {
        0 => CompressionMethod::FileStored,
        1 => CompressionMethod::FileShrunk,
        2 => CompressionMethod::FileReducedCompression1,
        3 => CompressionMethod::FileReducedCompression2,
        4 => CompressionMethod::FileReducedCompression3,
        5 => CompressionMethod::FileReducedCompression4,
        6 => CompressionMethod::FileImploded,
        7 => CompressionMethod::ReservedTokenizingCompressionAlgorithm,
        8 => CompressionMethod::FileDeflated,
        9 => CompressionMethod::FileDeflated64,
        10 => CompressionMethod::PKWAREDataCompressionLirarImploding,
        11 => CompressionMethod::PKWAREReserved11,
        12 => CompressionMethod::FileCompressedBZIP2,
        13 => CompressionMethod::PKWAREReserved13,
        14 => CompressionMethod::LZMA,
        15 => CompressionMethod::PKWAREReserved15,
        16 => CompressionMethod::IBMCMPSCCompression,
        17 => CompressionMethod::PKWAREReserved17,
        18 => CompressionMethod::FileCompressedIBMTERSE,
        19 => CompressionMethod::IBMLZ77,
        96 => CompressionMethod::JPEGVariant,
        97 => CompressionMethod::WavPack,
        98 => CompressionMethod::PPMdV1R1,
        99 => CompressionMethod::EncryptionMarker,
        _ => panic!(),
    };
    Ok((input, compression_method))
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // /// Test parsing of a zip containing only a 0 bit file called "empty"
    // fn it_parse_a_single_empty_file() {
    //     let file = include_bytes!("../test/single_empty_file.zip");
    //     assert_eq!(parse(file), Ok((&[][..], ZipFile { files: vec![] })));
    // }

    // #[test]
    // /// Test parsing of a zip conaining only a file named "test.txt" containing "test"
    // fn it_parse_a_single_file() {
    //     let file = include_bytes!("../test/single_file.zip");
    //     // println!("{:?}", file.length());
    //     assert_eq!(parse(file), Ok((&[][..], ZipFile { files: vec![] })));
    // }

    #[test]
    /// Test parsing a minimal zip, containing only End Of Central Directory
    fn it_parse_empty_zip() {
        let expected_res: &[u8] = &[][..];
        let file = &[
            0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let res = parse(file);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(expected_res, res.0);
    }

    #[test]
    /// Test parsing a zip, containing only an empty folder named "folder"
    fn it_parse_empty_folder_zip() {
        let expected_res: &[u8] = &[][..];
        let file = include_bytes!("../test/single_empty_folder.zip");
        let res = parse(file);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(expected_res, res.0);
        assert_eq!(b"folder/", res.1.files.get(0).unwrap().header.file_name);
    }

    #[test]
    /// Test parsing a zip, containing only an empty folder named "folder"
    fn it_parse_empty_folders_zip() {
        let expected_res: &[u8] = &[][..];
        let file = include_bytes!("../test/multiple_empty_folders.zip");
        let res = parse(file);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(expected_res, res.0);
        assert_eq!(b"folder0/", res.1.files.get(0).unwrap().header.file_name);
        assert_eq!(b"folder0/folder00/", res.1.files.get(1).unwrap().header.file_name);
        assert_eq!(b"folder1/", res.1.files.get(2).unwrap().header.file_name);
    }
}
