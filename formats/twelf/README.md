# TWELF file format

TWELF is the native executable file format of procyos. It wraps around ELF (for the most part) and offers the following features:

- multi-architecture “fat” binaries
- executable signing
- ease of integration with existing ELF loaders

All fields inside of TWELF files are little endian, even on big endian systems. The ELFs inside of a TWELF may be big endian.

## File Header

| Field | type | Meaning |
|-------|-|-|
| `magic` | `[u8; 4]` | Literal `TWLF` |
| `version` | `u32` | Literal `0` |
| `num_files` | `u32` | number of files included |
| `key_id` | `V0KeyId` | Key ID corresponding to the signing key |
| [padding] | [3 bytes] | 8 byte alignment for faster access. |
| `files` | `[FileInfo; num_files]` | File Metadata |
| `sig` | `Ed25519Signature` | Signature over all previous fields of the file |

A reader **MUST** check that the first 8 bytes match the fields in the table exactly. It also **MUST** verify that the signature is validly signed by the key with id `key_id`.

The rationale for why the file contains the Public Key ID and not the Public Key itself is that an implementation cannot “verify” the signature by taking the public key out of the header. To verify, the Ed25519 public key must necessarily be in your trusted key keyring.

## V0 Key ID

The V0 key ID is the byte `00` followed by the 32 bytes of the blake3 hash of the ed25519 public key used to sign the message. Implementations **MUST** ensure that the first byte is `00`.

## File Info

| Field | Type | Meaning |
|-|-|-|
| `mach_type` | `MachType` | Architecture this file is for |
| `subarch_type` | `u32` | Architecture specific subarchitecture identifier, for example an enumeration of required CPU features |
| `start_off` | `u64` | Offset of the file from the start of this executable. **RECOMMENDED** to be aligned to the page size of the architecture. |
| `file_len` | `u64` | Size of the file in bytes. **RECOMMENDED** to be aligned to the page size of the architecture. |
| `hash` | `Blake3bDigest` | Hash of the file from the first byte to the large byte |

In the event that the file loader loads past the end of the file, the implementation **MUST** set all bytes past the end of the file to all `00` bytes.

## Mach Type

Mach Type is an extension of ELF’s machine types. Values 0x0000-0xFFFF are the same as in ELF, after which our custom machine types are mapped.

Current extra machines are:

- `0x1_0000`: No machine. This is not an executable, but an auxilliary file for the binary, which is shared between all of the binaries. This file could include extra binary resources, permissions or service declarations or the like. The type of file is defined by the subarch_type.
- `0x1_0001`: WASM, without memory64 memory (rust target `wasm32-unknown-unknown`)
- `0x1_0002`: WASM, with memory64 memory (rust target `wasm64-unknown-unknown`)
