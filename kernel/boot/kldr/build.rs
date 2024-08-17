use std::{
    env,
    fs::File,
    io::{BufWriter, Write},
    path::Path,
};

use twelf::crypto::KeyId;

fn main() {
    let key_id =
        KeyId::deserialize(include_bytes!("../../../.secrets/twelf_public_key.id")).unwrap();

    let path = Path::new(&env::var("OUT_DIR").unwrap()).join("codegen.rs");
    let mut file = BufWriter::new(File::create(&path).unwrap());

    writeln!(
        &mut file,
        "static KEYRING: phf::Map<KeyId, &'static Lazy<PublicVerifyingKey>> = {};",
        phf_codegen::Map::new()
            .entry(key_id, "&VERIFYING_KEY")
            .build()
    )
    .unwrap();
}
