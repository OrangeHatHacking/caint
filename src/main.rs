use caint::app::App;
use caint::config::AppConfig;
use std::path::PathBuf;

fn print_usage() {
    eprintln!("Usage: caint <command> [options]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  run              Start the node (relay + messenger)");
    eprintln!("  init             Generate identity and print public keys");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --listen <addr>  Listen address (default: 0.0.0.0:9000)");
    eprintln!("  --data <path>    Storage directory (default: ./caint_data)");
    eprintln!("  --peer <addr>    Bootstrap peer address (can be repeated)");
    eprintln!("  --epoch <ms>     Epoch interval in ms (default: 1000)");
}

fn parse_args() -> Option<(String, AppConfig)> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        return None;
    }

    let command = args[1].clone();
    let mut config = AppConfig::default();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                i += 1;
                if i < args.len() {
                    config.listen_addr = args[i].clone();
                }
            }
            "--data" => {
                i += 1;
                if i < args.len() {
                    config.storage_path = PathBuf::from(&args[i]);
                }
            }
            "--peer" => {
                i += 1;
                if i < args.len() {
                    config.bootstrap_peers.push(args[i].clone());
                }
            }
            "--epoch" => {
                i += 1;
                if i < args.len() {
                    config.epoch_interval_ms = args[i].parse().unwrap_or(1000);
                }
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
            }
        }
        i += 1;
    }

    Some((command, config))
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "caint=info".parse().unwrap()),
        )
        .init();

    let (command, config) = match parse_args() {
        Some(c) => c,
        None => {
            print_usage();
            std::process::exit(1);
        }
    };

    match command.as_str() {
        "init" => {
            let app = App::new(config);
            println!("=== Caint Identity Generated ===");
            println!("X25519 Public Key: {}", app.identity_hex());
            println!("Ed25519 Public Key: {}", app.identity_ed_hex());
            println!("Storage: {:?}", app.config.storage_path);
            println!();
            println!(
                "To start this node:\n  caint run --listen {} --data {:?}",
                app.config.listen_addr, app.config.storage_path
            );
        }
        "run" => {
            let mut app = App::new(config);
            println!("=== Caint E2EE Messaging Node ===");
            println!("Identity: {}", app.identity_hex());
            println!("Listening: {}", app.config.listen_addr);
            if !app.config.bootstrap_peers.is_empty() {
                println!("Peers: {:?}", app.config.bootstrap_peers);
            }
            println!();
            app.run().await;
        }
        other => {
            eprintln!("Unknown command: {}", other);
            print_usage();
            std::process::exit(1);
        }
    }
}
