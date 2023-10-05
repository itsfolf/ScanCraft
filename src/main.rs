use std::{fmt, thread};
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::{Parser, ValueEnum};
use parking_lot::Mutex;

use scancraft::processing::SharedData;
use scancraft::scanner::{ScannerReceiver, ScanSession};
use scancraft::scanner::Scanner;
use scancraft::scanner::targets::{ScanRange, ScanRanges};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    mode: ScanMode,

    #[arg(long, short, help = "Subnet to scan (burst only)")]
    subnet: Option<String>,

    #[arg(long, short = 'n', default_value_t = 1, help = "Amount of threads to send packets on")]
    send_thread_count: u32,

    #[arg(long, default_value_t = false, help = "Don't initiate packets")]
    silent: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ScanMode {
    Burst,
    Strategic,
    Worker,
    Scraper,
}

impl fmt::Display for ScanMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ScanMode::Burst => write!(f, "Burst"),
            ScanMode::Strategic => write!(f, "Strategic"),
            ScanMode::Worker => write!(f, "Worker"),
            ScanMode::Scraper => write!(f, "Scraper")
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!("Starting...");
    println!("Mode: {}", args.mode);

    let source_port = 61000;
    let ping_timeout_secs = 60;
    let max_packets_per_second = 100000;

    let scanner = Scanner::new(source_port);

    let scanner_seed = scanner.seed;
    let scanner_writer = scanner.client.write.clone();

    let has_ended = Arc::new(AtomicBool::new(false));
    let shared_process_data = Arc::new(Mutex::new(SharedData {
        found_server_queue: VecDeque::new(),
        results: 0,
    }));

    let mut receiver = ScannerReceiver {
        shared_process_data: shared_process_data.clone(),
        scanner,
        has_ended: has_ended.clone(),
    };
    let recv_loop_thread = thread::spawn(move || {
        receiver.recv_loop(Duration::from_secs(ping_timeout_secs));
    });

    // start?
    match args.mode {
        ScanMode::Burst => {
            let mut ranges = ScanRanges::new();
            ranges.extend(vec![ScanRange::single_port(
                Ipv4Addr::new(185, 182, 186, 0),
                Ipv4Addr::new(185, 182, 187, 255),
                25565,
            )]);

            let session = ScanSession::new(ranges);
            let mut scanner_writer = scanner_writer.clone();
            let scanner_thread = thread::spawn(move || {
                session.run(max_packets_per_second, &mut scanner_writer, scanner_seed);
            });

            loop {
                if shared_process_data.lock().found_server_queue.is_empty() {
                    // wait a bit until next loop
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                let updating = shared_process_data.lock().found_server_queue
                    .drain(..).collect::<Vec<_>>();
                for (addr, data) in updating {
                    println!("Found server at {}: {:?}", addr, data);
                }

                if scanner_thread.is_finished() {
                    println!("Scanner has finished, waiting {} seconds to close recv loop...", { ping_timeout_secs });
                    tokio::time::sleep(Duration::from_secs(ping_timeout_secs)).await;
                    has_ended.store(true, Ordering::Relaxed);
                    recv_loop_thread.join().unwrap();
                    println!("Done!");
                    break;
                }
            }
        }
        _ => {
            println!("Not implemented yet {}", args.mode)
        }
    }

    Ok(())
}