use std::collections::HashSet;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
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
    #[command(description = "add ip to whitelist.")]
    Add(String),
}

/// Parse the text wrote on Telegram and check if that text is a valid command
/// or not, then match the command.
async fn message_handler(
    cx: UpdateWithCx<AutoSend<Bot>, Message>,
    whitelist: Arc<RwLock<HashSet<IpAddr>>>,
    rejected_addresses: Arc<RwLock<HashSet<IpAddr>>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    match cx.update.text() {
        Some(text) => {
            match BotCommand::parse(text, "buttons") {
                Ok(Command::Help) => {
                    // Just send the description of all commands.
                    cx.answer(Command::descriptions()).await?;
                }
                Ok(Command::Rejected) => {
                    cx.answer(format!(
                        "There are {} rejected addresses:\n{}",
                        rejected_addresses.read().unwrap().len(),
                        rejected_addresses
                            .read()
                            .unwrap()
                            .iter()
                            .map(|a| format!("{}\n", a.to_string()))
                            .collect::<String>()
                    ))
                    .await?;
                }
                Ok(Command::Add(ip)) => match ip.parse::<IpAddr>() {
                    Ok(ip) => {
                        whitelist.write().unwrap().insert(ip);
                        cx.answer(format!("IP {} is added to whitelist", ip))
                            .await?;
                    }
                    Err(e) => {
                        cx.answer(format!("IP cannot be parsed: {}", e))
                            .await?;
                    }
                },

                Ok(_) | Err(_) => {
                    cx.reply_to("Command not found!").await?;
                }
            }
        }
        None => {}
    }

    Ok(())
}

pub async fn start_bot(
    whitelist: Arc<RwLock<HashSet<IpAddr>>>,
    rejected_addresses: Arc<RwLock<HashSet<IpAddr>>>,
) {
    let bot = Bot::from_env().auto_send();

    //let bot_name: String = "merino_bot".to_string();
    //teloxide::commands_repl(bot, bot_name, answer).await;
    Dispatcher::new(bot)
        .messages_handler(|rx: DispatcherHandlerRx<AutoSend<Bot>, Message>| {
            UnboundedReceiverStream::new(rx).for_each_concurrent(None, move |cx| {
                let whitelist = whitelist.clone();
                let rejected = rejected_addresses.clone();
                async move {
                    message_handler(cx, whitelist, rejected)
                        .await
                        .log_on_error()
                        .await;
                }
            })
        })
        .dispatch()
        .await;
}
