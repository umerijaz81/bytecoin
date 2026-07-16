use std::io::{self, Read};

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() != 3 || arguments[1] != "descriptor" {
        eprintln!("usage: onyx-compiler-backend descriptor <circuit-k> < program.onxir");
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
    match onyx_zk::compiler_backend::compiler_vk_descriptor(&ir, k) {
        Ok(descriptor) => {
            for byte in descriptor {
                print!("{byte:02x}");
            }
            println!();
        }
        Err(error) => {
            eprintln!("compiler backend rejected IR: {error:?}");
            std::process::exit(3);
        }
    }
}
