use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main(){
    if let Err(e) = build_bpf() {
        eprint!("BPF builde is failed: {}", e);
        std::process::exit(1);
    }
}

fn build_bpf() -> Result<(), String>{
    let bpf_dir = PathBuf::from("../bpf");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bpf");
    
    if !bpf_dir.exists(){
        return Err(format!("BPF directory not found: {:?}", bpf_dir));
    }
    
    std::fs::create_dir_all(&out_dir).map_err(
        |e| format!("Failed to create output dir: {}", e)
    )?;

    let status = Command::new("make")
        .current_dir(&out_dir)
        .status()
        .map_err(|e| format!("Failed to execute make: {}", e))?;

    if !status.success(){
        return Err(format!("BPF compilatian failed with exit code: {:?}", status.code()));
    }

    let bpf_output = out_dir.join("secure_agent.bpf.o");
    if !bpf_output.exists(){
        return Err(format!("BPF output file not found: {:?}", bpf_output));
    }

    println!("cargo:rerun-if-changed=../bpf/src/main.c");
    println!("cargo:rerun-if-changed=../bpf/src/handlers.c");
    println!("cargo:rerun-if-changed=../bpf/src/common.h");
    println!("cargo:rerun-if-changed=../bpf/Makefile");

    Ok(())
}