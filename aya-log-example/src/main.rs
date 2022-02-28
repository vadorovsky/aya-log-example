use aya::{include_bytes_aligned, Bpf};
use aya::{programs::BtfTracePoint, Btf};
use aya_log::BpfLogger;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use std::{
    convert::TryInto,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    thread,
    time::Duration,
};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // This will include youe eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/aya-log-example"
    ))?;

    BpfLogger::init(&mut bpf)?;

    let btf = Btf::from_sys_fs()?;
    let program: &mut BtfTracePoint = bpf.program_mut("sched_process_fork").unwrap().try_into()?;
    program.load("sched_process_fork", &btf)?;
    program.attach()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    println!("Waiting for Ctrl-C...");
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(500))
    }
    println!("Exiting...");

    Ok(())
}
