use ff::PrimeField;
use halo2_proofs::pasta::Fp;
use std::io::{self, Read};

fn fields(text: &str) -> Result<Vec<Fp>, ()> {
    if text == "-" {
        return Ok(Vec::new());
    }
    let parts: Vec<_> = text.split(',').collect();
    if parts.len() > 8192 {
        return Err(());
    }
    parts
        .into_iter()
        .map(|part| {
            if part.len() != 64
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(());
            }
            let mut bytes = [0u8; 32];
            for (index, pair) in part.as_bytes().chunks_exact(2).enumerate() {
                bytes[index] = u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| ())?, 16)
                    .map_err(|_| ())?;
            }
            Option::<Fp>::from(Fp::from_repr(bytes)).ok_or(())
        })
        .collect()
}

fn print_hex(bytes: &[u8]) {
    for byte in bytes {
        print!("{byte:02x}");
    }
    println!();
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    if !matches!(
        (arguments.get(1).map(String::as_str), arguments.len()),
        (Some("descriptor"), 3) | (Some("prove"), 5)
    ) {
        eprintln!("usage: onyx-compiler-backend descriptor <circuit-k> < program.onxir");
        eprintln!("   or: onyx-compiler-backend prove <circuit-k> <witness-fields> <public-fields> < program.onxir");
        std::process::exit(2);
    }
    let k: u32 = arguments[2].parse().unwrap_or_else(|_| {
        eprintln!("invalid circuit k");
        std::process::exit(2);
    });
    let mut ir = Vec::new();
    if io::stdin().read_to_end(&mut ir).is_err() {
        eprintln!("failed to read canonical IR");
        std::process::exit(2);
    }
    if arguments[1] == "descriptor" {
        match onyx_zk::compiler_backend::compiler_vk_descriptor(&ir, k) {
            Ok(descriptor) => print_hex(&descriptor),
            Err(error) => {
                eprintln!("compiler backend rejected IR: {error:?}");
                std::process::exit(3);
            }
        }
    } else {
        let witness = fields(&arguments[3]).unwrap_or_else(|_| {
            eprintln!("invalid canonical witness fields");
            std::process::exit(2);
        });
        let public = fields(&arguments[4]).unwrap_or_else(|_| {
            eprintln!("invalid canonical public fields");
            std::process::exit(2);
        });
        match onyx_zk::compiler_backend::create_compiler_proof(
            &ir,
            k,
            onyx_zk::compiler_backend::CompilerWitness {
                parameters: witness,
            },
            &public,
        ) {
            Ok(proof) => print_hex(&proof),
            Err(error) => {
                eprintln!("compiler backend proof failed: {error:?}");
                std::process::exit(3);
            }
        }
    }
}
