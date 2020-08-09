use config::{Config, File};
use futures::TryFutureExt;
use log::{debug, warn};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use igmas_shared::{DoneResponse, DoneMessage, ValidateTokenRequest, ValidateTokenResponse, ROOT_URL};

use std::{
    fs::File as StdFile,
    io::Write,
};

#[tokio::main]
async fn main() {
    env_logger::init();
    let config = {
        let mut config = Config::new();
        let config_path = dirs::config_dir()
            .expect("Unable to find a config directory. This likely isn't a supported platform.")
            .join(".igmas.json");
        if let Err(e) = config.merge(File::with_name(config_path.to_str().unwrap())) {
            debug!(
                "Failed to load config at {:?}, due to {:?} creating a new one.",
                config_path, e
            );
            // TODO: Retrieve auth token from args and save it to the config, unless we're also told to not save the token.
            println!(
                "Couldn't find existing igmas token, please enter your auth token from {}/account",
                ROOT_URL
            ); // TODO: Is this URL right?
            let mut auth_token = String::new();
            loop {
                print!("> ");
                std::io::stdout().flush().unwrap();
                std::io::stdin().read_line(&mut auth_token).unwrap();
                if auth_token.to_lowercase() == "quit" {
                    std::process::exit(1);
                }
                let result = send_json_to_url::<_, _, ValidateTokenResponse>(
                    &format!("{}/validate_token", ROOT_URL),
                    &ValidateTokenRequest {
                        auth_token: auth_token.clone(),
                    },
                ).await;
                match result {
                    Ok(ValidateTokenResponse { is_valid }) => {
                        if is_valid {
                            break;
                        } else {
                            println!("Token is invalid, please try again, or type Quit");
                        }
                    }
                    Err(e) => {
                        println!("Error sending request: {:?}, please try again later or file an issue on GitHub.", e);
                        std::process::exit(1);
                    }
                }
            }
            let new_config = ClientConfig { auth_token };
            let new_config_json = serde_json::to_string_pretty(&new_config).unwrap();
            if let Err(e) =
                StdFile::create(&config_path).map(|mut f| f.write_all(new_config_json.as_bytes()))
            {
                warn!("Failed to write config, {:?}", e);
            }
            new_config
        } else {
            config
                .try_into::<ClientConfig>()
                .expect("Found config but it's a bad format.")
        }
    };
    let result = send_json_to_url::<_, _, DoneResponse>(
        &format!("{}/done", ROOT_URL),
        &DoneMessage {
            auth_token: config.auth_token.clone(),
            done_name: String::new(), // TODO: Populate this from args
            host_name: hostname::get().unwrap_or_default().into_string().unwrap_or_default(),
        },
    ).await;
    match result {
        Ok(DoneResponse { notification_sent, remote_response }) => {
            if !notification_sent {
                println!("igmas notification not sent!");
            }
            if let Some(remote_response) = remote_response {
                println!("Server response: \"{}\"", remote_response);
            }
        }
        Err(e) => {
            println!("Error sending request: {:?}, please try again later or file an issue on GitHub.", e);
        }
    }
}

#[derive(Default, Deserialize, Serialize)]
struct ClientConfig {
    auth_token: String,
}

async fn send_json_to_url<U: reqwest::IntoUrl, T: Serialize + ?Sized, R: DeserializeOwned>(
    url: U,
    json: &T,
) -> Result<R, reqwest::Error> {
    reqwest::Client::new()
        .post(url)
        .json(json)
        .send()
        .and_then(|r| r.json::<R>())
        .await
}
