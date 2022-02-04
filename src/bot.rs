use merino::Lists;
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

/// Parse the text wrote on Telegram and check if that text is a valid command
/// or not, then match the command.
async fn message_handler(
    cx: UpdateWithCx<AutoSend<Bot>, Message>,
    lists: Arc<Lists>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Some(text) = cx.update.text() {
        let message = match BotCommand::parse(text, "buttons") {
            Ok(Command::Help) => {
                // Just send the description of all commands.
                Command::descriptions()
            }
            Ok(Command::Rejected) => {
                lists.print_rejected()
                /*
                format!(
                    "There are \{\} rejected addresses:\n{}",
                    rejected_addresses.read().unwrap().len(),
                    rejected_addresses
                        .read()
                        .unwrap()
                        .iter()
                        .map(|a| format!("{}\n", a))
                        .collect::<String>()
                )
                */
            }
            Ok(Command::Whitelist) => lists.print_whitelisted(),
            Ok(Command::Add(ip)) => match ip.parse::<IpAddr>() {
                Ok(ip) => lists.add_to_whitelist(&ip),
                Err(e) => {
                    format!("IP cannot be parsed: {}", e)
                }
            },

            Err(_) => "Command not found!".to_string(),
        };

        cx.reply_to(message).await?;
    }

    Ok(())
}

pub async fn start_bot(whitelist_file: Arc<Path>, lists: Arc<Lists>) {
    let bot = Bot::from_env().auto_send();

    info!("Starting telegram bot...");

    Dispatcher::new(bot)
        .messages_handler(|rx: DispatcherHandlerRx<AutoSend<Bot>, Message>| {
            UnboundedReceiverStream::new(rx).for_each_concurrent(None, move |cx| {
                //let whitelist_file = whitelist_file.clone();
                let lists = lists.clone();
                async move {
                    message_handler(cx, lists).await.log_on_error().await;
                }
            })
        })
        .dispatch()
        .await;
}
