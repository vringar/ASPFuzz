use chrono::Local;
use clap::{command, Parser};

use libasp::config::{borrow_global_conf, init_global_conf};

use std::{env, path::PathBuf, process::exit};

/// Fuzzing the on-chip-bootloader from different AMD Zen generations.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)] // Read from Cargo.toml
struct Args {
    /// YAML config file path
    #[arg(short, long)]
    yaml_path: PathBuf,

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
    if !cli_args.yaml_path.exists() {
        println!(
            "YAML file path does not exist: {}",
            cli_args.yaml_path.display()
        );
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
    init_global_conf(&cli_args.yaml_path, num_cores, run_dir.clone());
    let conf = borrow_global_conf().unwrap();

    //Check if pathes exist
    if !conf.qemu.on_chip_bl_path.exists() {
        println!(
            "On-chip-bl file path does not exist: {}",
            conf.qemu.on_chip_bl_path.display()
        );
        exit(4);
    }
    if !conf.flash.base.exists() {
        println!(
            "UEFI file path does not exist: {}",
            &conf.flash.base.display()
        );
        exit(5);
    }

    // Create arguments to start QEMU with
    let mut qemu_args: Vec<String> = vec![env::args().next().unwrap()];
    println!("QEMU arguments: {:?}", qemu_args);
    if conf.debug {
        qemu_args.append(&mut vec![
            "-d".to_string(),
            "trace:ccp_*,trace:psp_*".to_string(),
            "-D".to_string(),
            format!["{}/logs/qemu.log", run_dir.display()],
        ]);
        log::info!("Debug mode enabled");
    }
    qemu_args.extend(vec![
        "--machine".to_string(),
        conf.qemu.zen.get_qemu_machine_name().to_string(),
        "--nographic".to_string(),
        "-device".to_string(),
        format![
            "loader,file={}/{},addr=0xffff0000,force-raw=on",
            env::var("PROJECT_DIR").unwrap(),
            &conf.qemu.on_chip_bl_path.display()
        ],
        "-global".to_string(),
        format![
            "driver=amd_psp.smnflash,property=flash_img,value={}/{}",
            env::var("PROJECT_DIR").unwrap(),
            &conf.flash.base.display()
        ],
        "-bios".to_string(),
        format![
            "{}/{}",
            env::var("PROJECT_DIR").unwrap(),
            &conf.flash.base.display()
        ],
        "-monitor".to_string(),
        "none".to_string(),
    ]);

    qemu_args
}
