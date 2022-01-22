use crate::Merino;
use std::collections::HashSet;
use std::error::Error;
use std::net::IpAddr;
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

async fn answer(
    cx: UpdateWithCx<AutoSend<Bot>, Message>,
    command: Command,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    match command {
        Command::Help => cx.answer(Command::descriptions()).await?,
        Command::Rejected => cx.answer("rejected list").await?,
        Command::Add(username) => {
            cx.answer(format!("Your username is @{}.", username))
                .await?
        }
    };

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
        .messages_handler(move |rx: DispatcherHandlerRx<AutoSend<Bot>, Message>| {
            let whitelist = whitelist.clone();
            let rejected = rejected_addresses.clone();
            
            UnboundedReceiverStream::new(rx).for_each_concurrent(None, |message| async move {
                let white = Arc::clone(&whitelist);
                message
                    .answer(format!(
                        "Whitelist contains {} entries. rejected_addresses contains {} entries.",
                        whitelist.read().unwrap().len(),
                        rejected.read().unwrap().len(),
                    ))
                    .await
                    .log_on_error()
                    .await;
            })
        })
        .dispatch()
        .await;
}
