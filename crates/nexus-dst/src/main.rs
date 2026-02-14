use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

use nexus_dst::engine::SimulationEngine;
use nexus_dst::report::SimulationReport;
use nexus_dst::scenario::Scenario;
use nexus_dst::scenarios;

#[derive(Parser)]
#[command(name = "nexus-dst", about = "Deterministic Simulation Testing for Nexus SFU")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a simulation scenario
    Run {
        /// Path to scenario TOML file (optional if --builtin is used)
        #[arg(required_unless_present = "builtin", conflicts_with = "builtin")]
        scenario: Option<PathBuf>,
        /// Run a built-in scenario by name (use 'list' to see available)
        #[arg(long, short = 'b')]
        builtin: Option<String>,
        /// Random seed for reproducibility
        #[arg(long)]
        seed: Option<u64>,
        /// Enable detailed event-by-event output
        #[arg(long)]
        verbose: bool,
        /// Output results in JSON format
        #[arg(long)]
        json: bool,
        /// Maximum simulation virtual time in seconds
        #[arg(long)]
        timeout: Option<u64>,
    },
    /// Validate a scenario file without executing it
    Check {
        /// Path to scenario TOML file
        scenario: PathBuf,
    },
    /// List built-in example scenarios
    List,
    /// Generate a formatted report from saved simulation results
    Report {
        /// Path to JSON results file
        results: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Command::Run {
            scenario,
            builtin,
            seed,
            verbose,
            json,
            timeout,
        } => cmd_run(scenario, builtin, seed, verbose, json, timeout),
        Command::Check { scenario } => cmd_check(scenario),
        Command::List => cmd_list(),
        Command::Report { results } => cmd_report(results),
    };

    process::exit(exit_code);
}

fn cmd_run(
    path: Option<PathBuf>,
    builtin: Option<String>,
    seed: Option<u64>,
    verbose: bool,
    json: bool,
    timeout: Option<u64>,
) -> i32 {
    // 1. Get scenario content from file or built-in
    let content = if let Some(name) = builtin {
        match scenarios::get_builtin_scenario(&name) {
            Some(toml) => toml,
            None => {
                eprintln!("Unknown built-in scenario: '{}'", name);
                eprintln!("Use 'nexus-dst list' to see available scenarios.");
                return 1;
            }
        }
    } else if let Some(path) = path {
        match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error reading scenario file '{}': {}", path.display(), e);
                return 1;
            }
        }
    } else {
        eprintln!("Either a scenario file or --builtin must be provided");
        return 1;
    };

    // 2. Parse scenario
    let scenario = match Scenario::from_toml(&content) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error parsing scenario: {}", e);
            return 1;
        }
    };

    // 3. Validate scenario
    if let Err(errors) = scenario.validate() {
        eprintln!("Scenario validation failed:");
        for err in &errors {
            eprintln!("  - {}", err);
        }
        return 1;
    }

    // 4. Determine seed
    let seed = match seed {
        Some(s) => {
            if verbose {
                eprintln!("Using provided seed: {}", s);
            }
            s
        }
        None => {
            let s = rand::random::<u64>();
            eprintln!("Generated seed: {}", s);
            s
        }
    };

    // 5. Create engine and run simulation
    let mut engine = SimulationEngine::new(scenario, seed, verbose, timeout);
    let report = engine.run();

    // 6. Output report
    if json {
        match report.to_json() {
            Ok(json_str) => println!("{}", json_str),
            Err(e) => {
                eprintln!("Error serializing report to JSON: {}", e);
                return 1;
            }
        }
    } else {
        print!("{}", report.to_human_readable());
    }

    // 7. Exit code based on pass/fail
    if report.passed { 0 } else { 1 }
}

fn cmd_check(path: PathBuf) -> i32 {
    // Read scenario file
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading scenario file '{}': {}", path.display(), e);
            return 1;
        }
    };

    // Parse scenario
    let scenario = match Scenario::from_toml(&content) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error parsing scenario: {}", e);
            return 1;
        }
    };

    // Validate scenario
    match scenario.validate() {
        Ok(()) => {
            println!("Scenario '{}' is valid.", scenario.name);
            println!("  Participants: {}", scenario.participants.len());
            println!("  Tracks:       {}", scenario.tracks.len());
            println!("  Subscriptions:{}", scenario.subscriptions.len());
            println!("  Faults:       {}", scenario.faults.len());
            println!("  Assertions:   {}", scenario.assertions.len());
            0
        }
        Err(errors) => {
            eprintln!("Scenario validation failed:");
            for err in &errors {
                eprintln!("  - {}", err);
            }
            1
        }
    }
}

fn cmd_list() -> i32 {
    println!("Built-in scenarios:");
    println!();
    for (name, description) in scenarios::list_builtin_scenarios() {
        println!("  {:<25} {}", name, description);
    }
    0
}

fn cmd_report(path: PathBuf) -> i32 {
    // Read JSON results file
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading results file '{}': {}", path.display(), e);
            return 1;
        }
    };

    // Parse report
    let report = match SimulationReport::from_json(&content) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error parsing results JSON: {}", e);
            return 1;
        }
    };

    // Output human-readable format
    print!("{}", report.to_human_readable());

    if report.passed { 0 } else { 1 }
}
