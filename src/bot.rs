use std::collections::HashSet;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};
use teloxide::{prelude::*, utils::command::BotCommand};
use tokio_stream::wrappers::UnboundedReceiverStream;

#[derive(BotCommand)]
#[command(rename = "lowercase", description = "These commands are supported:")]
enum Command {
    #[command(description = "display this text.")]
    Help,
    #[command(description = "show all rejected addresses")]
    Rejected,
    #[command(description = "show all whitelisted addresses")]
    Whitelist,
    #[command(description = "add ip to whitelist.")]
    Add(String),
}

fn add_ip_to_whitelist(
    ip: IpAddr,
    whitelist: Arc<RwLock<HashSet<IpAddr>>>,
    whitelist_file: Arc<Path>,
) -> String {
    let contains = {
        let mut whitelist = whitelist.write().unwrap();
        let contains = whitelist.contains(&ip);
        whitelist.insert(ip);
        contains
    };

    if contains {
        format!("IP {} is already in whitelist", ip)
    } else {
        let message: String = {
            match OpenOptions::new().append(true).open(whitelist_file) {
                Ok(mut file) => {
                    let message = if file.metadata().unwrap().len() > 0 {
                        format!("\n{}", ip)
                    } else {
                        format!("{}", ip)
                    };

                    match file.write(message.as_bytes()) {
                        Ok(_) => format!("IP {} is added to whitelist", ip),
                        Err(e) => format!(
                            "IP {} is added to whitelist, but not saved to file, because: {:?}",
                            ip, e
                        ),
                    }
                }
                Err(e) => format!(
                    "IP {} is added to whitelist, but not saved to file, because: {:?}",
                    ip, e
                ),
            }
        };

        info!("{}", message);
        message
    }
}

/// Parse the text wrote on Telegram and check if that text is a valid command
/// or not, then match the command.
async fn message_handler(
    cx: UpdateWithCx<AutoSend<Bot>, Message>,
    whitelist: Arc<RwLock<HashSet<IpAddr>>>,
    rejected_addresses: Arc<RwLock<HashSet<IpAddr>>>,
    whitelist_file: Arc<Path>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Some(text) = cx.update.text() {
        let message = match BotCommand::parse(text, "buttons") {
            Ok(Command::Help) => {
                // Just send the description of all commands.
                Command::descriptions()
            }
            Ok(Command::Rejected) => {
                format!(
                    "There are {} rejected addresses:\n{}",
                    rejected_addresses.read().unwrap().len(),
                    rejected_addresses
                        .read()
                        .unwrap()
                        .iter()
                        .map(|a| format!("{}\n", a))
                        .collect::<String>()
                )
            }
            Ok(Command::Whitelist) => {
                format!(
                    "There are {} addresses in whitelist:\n{}",
                    whitelist.read().unwrap().len(),
                    whitelist
                        .read()
                        .unwrap()
                        .iter()
                        .map(|a| format!("{}\n", a))
                        .collect::<String>()
                )
            }
            Ok(Command::Add(ip)) => match ip.trim().parse::<IpAddr>() {
                Ok(ip) => add_ip_to_whitelist(ip, whitelist, whitelist_file),
                Err(e) => format!("IP cannot be parsed: {}", e),
            },

            Err(_) => "Command not found!".to_string(),
        };

        cx.reply_to(message).await?;
    }

    Ok(())
}

pub async fn start_bot(
    whitelist: Arc<RwLock<HashSet<IpAddr>>>,
    rejected_addresses: Arc<RwLock<HashSet<IpAddr>>>,
    whitelist_file: Arc<Path>,
) {
    let bot = Bot::from_env().auto_send();

    info!("Starting telegram bot...");

    Dispatcher::new(bot)
        .messages_handler(|rx: DispatcherHandlerRx<AutoSend<Bot>, Message>| {
            UnboundedReceiverStream::new(rx).for_each_concurrent(None, move |cx| {
                let whitelist = whitelist.clone();
                let rejected = rejected_addresses.clone();
                let whitelist_file = whitelist_file.clone();
                async move {
                    message_handler(cx, whitelist, rejected, whitelist_file)
                        .await
                        .log_on_error()
                        .await;
                }
            })
        })
        .dispatch()
        .await;
}
