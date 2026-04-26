mod commands;
mod output;

use std::path::PathBuf;
use std::str::FromStr;

use agentlint_core::{file_type::TreatAs, finding::Severity};
use clap::{Parser, Subcommand};

use commands::check::{CheckConfig, OutputFormat};

#[derive(Parser)]
#[command(name = "agentlint", version, about = "Static analyzer for AI agent configuration files")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan files for agent security issues
    Check {
        /// Paths to scan (files or directories)
        paths: Vec<PathBuf>,

        /// Output format
        #[arg(long, default_value = "human", value_enum)]
        format: OutputFormat,

        /// Minimum severity level to report
        #[arg(long, default_value = "warn")]
        severity: String,

        /// Read from stdin instead of files
        #[arg(long)]
        stdin: bool,

        /// Filename hint when using --stdin
        #[arg(long)]
        filename: Option<String>,

        /// Treat all scanned markdown files as agent instructions
        #[arg(long)]
        treat_as: Option<String>,
    },

    /// Explain a specific rule
    Explain {
        /// Rule ID (e.g. AGT020)
        rule_id: String,
    },

    /// List all available rules
    #[command(name = "list-rules")]
    ListRules,

    /// Auto-fix fixable findings in files
    Fix {
        /// Paths to fix (files only)
        paths: Vec<PathBuf>,

        /// Treat all scanned markdown files as agent instructions
        #[arg(long)]
        treat_as: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    let exit_code = match run(cli) {
        Ok(has_findings) => {
            if has_findings { 1 } else { 0 }
        }
        Err(e) => {
            eprintln!("agentlint: internal error: {e}");
            2
        }
    };

    std::process::exit(exit_code);
}

fn run(cli: Cli) -> anyhow::Result<bool> {
    match cli.command {
        Commands::Check { paths, format, severity, stdin, filename, treat_as } => {
            let min_severity = Severity::from_str(&severity)
                .map_err(|e| anyhow::anyhow!(e))?;
            let treat_as = treat_as
                .as_deref()
                .map(TreatAs::from_str)
                .transpose()
                .map_err(|e| anyhow::anyhow!(e))?;

            let cfg = CheckConfig {
                paths,
                format,
                min_severity,
                stdin,
                filename,
                treat_as,
            };
            commands::check::run(cfg)
        }

        Commands::Explain { rule_id } => {
            commands::explain::run(&rule_id);
            Ok(false)
        }

        Commands::ListRules => {
            commands::list_rules::run();
            Ok(false)
        }

        Commands::Fix { paths, treat_as } => {
            let treat_as = treat_as
                .as_deref()
                .map(TreatAs::from_str)
                .transpose()
                .map_err(|e| anyhow::anyhow!(e))?;
            commands::fix::run(paths, treat_as)?;
            Ok(false)
        }
    }
}
