use chrono::Local;
use clap::{command, Parser};
use libafl::monitors::MultiMonitor;
use libasp::{borrow_global_conf, get_run_conf, init_global_conf};
use std::io::Write;
use std::sync::Mutex;
use std::{
    cell::RefCell,
    env,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    process::exit,
};

/// Fuzzing the on-chip-bootloader from different AMD Zen generations.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)] // Read from Cargo.toml
struct Args {
    /// YAML config file path
    #[arg(short, long)]
    yaml_path: String,

    /// Run directory name
    #[arg(short, long)]
    run_dir_name: Option<String>,

    /// Number of cores
    #[arg(short, long)]
    num_cores: Option<u32>,
}

pub fn parse_args() -> Vec<String> {
    let cli_args = Args::parse();
    // Parse YAML config
    if !Path::new(&cli_args.yaml_path).exists() {
        println!("YAML file path does not exist: {}", cli_args.yaml_path);
        exit(2);
    }
    let date = Local::now();
    let run_dir = if let Some(run_dir_name) = cli_args.run_dir_name {
        PathBuf::from(format!("runs/{}", run_dir_name))
    } else {
        PathBuf::from(format!("runs/{}", date.format("%Y-%m-%d_%H:%M")))
    };
    let num_cores = if let Some(num_cores) = cli_args.num_cores {
        num_cores
    } else {
        println!("For multicore fuzzing a core number must be provided (`cargo make run_fast -h`)");
        exit(3);
    };
    init_global_conf(&cli_args.yaml_path, num_cores, run_dir);
    let conf = borrow_global_conf().unwrap();

    // For multicore fuzzing a core number must be provided

    //Check if pathes exist
    if !Path::new(&conf.qemu_on_chip_bl_path).exists() {
        println!(
            "On-chip-bl file path does not exist: {}",
            &conf.qemu_on_chip_bl_path
        );
        exit(4);
    }
    if !Path::new(&conf.flash_base).exists() {
        println!("UEFI file path does not exist: {}", &conf.flash_base);
        exit(5);
    }

    // Handle Zen generation
    if ![
        String::from("Zen1"),
        String::from("Zen+"),
        String::from("Zen2"),
        String::from("Zen3"),
        String::from("Zen4"),
        String::from("ZenTesla"),
    ]
    .contains(&conf.qemu_zen)
    {
        println!("{} not a valid Zen generation.", &conf.qemu_zen);
        std::process::exit(6);
    }
    let zen_generation: &str;
    if conf.qemu_zen == *"Zen1" {
        zen_generation = "amd-psp-zen";
    } else if conf.qemu_zen == *"Zen+" {
        zen_generation = "amd-psp-zen+";
    } else if conf.qemu_zen == *"Zen2" {
        zen_generation = "amd-psp-zen2";
    } else if conf.qemu_zen == *"Zen3" {
        zen_generation = "amd-psp-zen3";
    } else if conf.qemu_zen == *"ZenTesla" {
        zen_generation = "amd-psp-zentesla";
    } else {
        println!("{} generation not supported yet.", &conf.qemu_zen);
        std::process::exit(7);
    }

    // Create arguments to start QEMU with
    let mut qemu_args: Vec<String> = vec![env::args().next().unwrap()];
    #[cfg(feature = "multicore")]
    qemu_args.append(&mut vec![
        "-trace".to_string(),
        "file=/dev/null".to_string(),
    ]);
    #[cfg(feature = "debug")]
    qemu_args.append(&mut vec![
        "-d".to_string(),
        "trace:ccp_*,trace:psp_*".to_string(),
    ]);
    qemu_args.extend(vec![
        "--machine".to_string(),
        zen_generation.to_string(),
        "--nographic".to_string(),
        "-device".to_string(),
        format![
            "loader,file={}/{},addr=0xffff0000,force-raw=on",
            env::var("PROJECT_DIR").unwrap(),
            &conf.qemu_on_chip_bl_path
        ],
        "-global".to_string(),
        format![
            "driver=amd_psp.smnflash,property=flash_img,value={}/{}",
            env::var("PROJECT_DIR").unwrap(),
            &conf.flash_base
        ],
        "-bios".to_string(),
        format!["{}/{}", env::var("PROJECT_DIR").unwrap(), &conf.flash_base],
    ]);

    qemu_args
}
