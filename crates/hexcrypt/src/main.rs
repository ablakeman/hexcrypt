use clap::{Parser, Subcommand};

mod client;
mod server;

#[derive(Parser)]
#[command(name = "hexcrypt", version, about = "Zero-knowledge one-time secret drop")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Encrypt a file (or stdin) and upload it. Prints the one-time URL.
    Send {
        /// File to send. Omit or "-" to read stdin.
        file: Option<String>,
        /// Lifetime: 1h, 1d or 7d.
        #[arg(short, long, default_value = "1d")]
        expires: String,
        /// Server base URL.
        #[arg(short, long, env = "HEXCRYPT_SERVER", default_value = "https://hexcrypt.com")]
        server: String,
    },
    /// Fetch and decrypt a secret URL. Burns it on the server.
    Get {
        url: String,
        /// Write output here instead of stdout / the original filename.
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Run the server (API + web UI).
    Serve(server::Opts),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Send { file, expires, server } => client::send(file, &expires, &server).await,
        Cmd::Get { url, output } => client::get(&url, output).await,
        Cmd::Serve(opts) => server::run(opts).await,
    }
}
