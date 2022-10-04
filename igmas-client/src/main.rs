use config::{Config, File};
use futures::TryFutureExt;
use log::{debug, warn};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use igmas_shared::{
    DoneMessage, DoneResponse, ValidateTokenRequest, ValidateTokenResponse, ROOT_URL,
};

use std::{
    env,
    ffi::{OsString, OsStr},
    fs::File as StdFile,
    io::{Error as IoError, Write},
    path::{Path, PathBuf},
    process::{Child, Command},
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[tokio::main]
async fn main() {
    env_logger::init();
    let config = {
        let config_path = dirs::config_dir()
            .expect("Unable to find a config directory. This likely isn't a supported platform.")
            .join(".igmas.json");
        let build_result = Config::builder()
            .add_source(File::with_name(config_path.to_str().unwrap()))
            .build();
        match build_result {
            Err(e) => {
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
                /*loop {
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
                }*/
                let new_config = ClientConfig {
                    auth_token,
                    shell_path: None,
                    execution_shell: ShellOption::default(),
                };
                let new_config_json = serde_json::to_string_pretty(&new_config).unwrap();
                if let Err(e) = StdFile::create(&config_path)
                    .map(|mut f| f.write_all(new_config_json.as_bytes()))
                {
                    warn!("Failed to write config, {:?}", e);
                }
                new_config
            }
            Ok(config) => config
                .try_deserialize()
                .expect("Found config but it's a bad format."),
        }
    };
    let execution_result = config
        .execution_shell
        .start(
            &config
                .shell_path
                .map(PathBuf::from)
                .unwrap_or_else(|| config.execution_shell.default_path()),
            env::args_os().skip(1),
        )
        .map(|mut c| c.wait());
    let result = send_json_to_url::<_, _, DoneResponse>(
        &format!("{}/done", ROOT_URL),
        &DoneMessage {
            auth_token: config.auth_token.clone(),
            done_name: String::new(), // TODO: Populate this from args
            host_name: hostname::get()
                .unwrap_or_default()
                .into_string()
                .unwrap_or_default(),
        },
    )
    .await;
    match result {
        Ok(DoneResponse {
            notification_sent,
            remote_response,
        }) => {
            if !notification_sent {
                println!("igmas notification not sent!");
            }
            if let Some(remote_response) = remote_response {
                println!("Server response: \"{}\"", remote_response);
            }
        }
        Err(e) => {
            println!(
                "Error sending request: {:?}, please try again later or file an issue on GitHub.",
                e
            );
        }
    }
}

#[derive(Default, Deserialize, Serialize)]
struct ClientConfig {
    auth_token: String,
    execution_shell: ShellOption,
    shell_path: Option<String>,
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

#[derive(Deserialize, Serialize)]
enum ShellOption {
    #[cfg(windows)]
    /// cmd.exe
    Cmd,
    #[cfg(windows)]
    /// powershell.exe
    PowerShell,
    #[cfg(windows)]
    /// pwsh.exe
    PowerShellCore,
    Bash,
    Ash,
    Zsh,
    Ksh,
    Csh,
    Sh,
}

impl ShellOption {
    fn default_path(&self) -> PathBuf {
        PathBuf::from(match self {
            #[cfg(windows)]
            ShellOption::Cmd => "C:\\Windows\\system32\\cmd.exe",
            #[cfg(windows)]
            ShellOption::PowerShell => {
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            }
            #[cfg(windows)]
            ShellOption::PowerShellCore => {
                if cfg!(target_os = "windows") {
                    "C:\\Program Files\\PowerShell\\7\\pwsh.exe"
                } else {
                    "/usr/bin/pwsh"
                }
            }
            ShellOption::Bash => "/bin/bash",
            ShellOption::Zsh => "/bin/zsh",
            ShellOption::Sh => "/bin/sh",
            // TODO: Are these right?
            ShellOption::Ksh => "/bin/ksh",
            ShellOption::Csh => "/bin/csh",
            ShellOption::Ash => "/bin/ash",
        })
    }

    fn start(&self, path: &Path, args: impl Iterator<Item = OsString>) -> Result<Child, IoError> {
        let mut cmd = Command::new(path);
        match self {
            #[cfg(windows)]
            ShellOption::Cmd => {
                cmd.arg("/C");
                let mut a = OsString::from("\"");
                for arg in args {
                    a.push(arg);
                    a.push(" ");
                }
                a.push("\"");
                cmd.raw_arg(a);
            },
            #[cfg(windows)]
            ShellOption::PowerShell | ShellOption::PowerShellCore => {
                cmd.arg("-Command");
                let mut a = OsString::from("\"");
                for arg in args {
                    let arg_needs_quotes = arg.to_string_lossy().contains(' ');
                    if arg_needs_quotes {
                        a.push("'");
                    }
                    a.push(arg);
                    if arg_needs_quotes {
                        a.push("'");
                    }
                    a.push(" ");
                }
                a.push("\"");
                cmd.raw_arg(a);
            }
            ShellOption::Ash
            | ShellOption::Ksh
            | ShellOption::Zsh
            | ShellOption::Csh
            | ShellOption::Sh
            | ShellOption::Bash => {
                cmd.arg("-c");
                let mut a = OsString::new();
                for arg in args {
                    a.push(arg);
                    a.push(" ");
                }
                cmd.arg(a);
            }
        };
        cmd.spawn()
    }
}

#[cfg(target_os = "linux")]
impl Default for ShellOption {
    fn default() -> Self {
        Self::Bash
    }
}

#[cfg(target_os = "netbsd")]
impl Default for ShellOption {
    fn default() -> Self {
        Self::Ash
    }
}

#[cfg(target_os = "freebsd")]
impl Default for ShellOption {
    fn default() -> Self {
        Self::Csh
    }
}

#[cfg(target_os = "openbsd")]
impl Default for ShellOption {
    fn default() -> Self {
        Self::Ksh
    }
}

#[cfg(target_os = "windows")]
impl Default for ShellOption {
    fn default() -> Self {
        Self::PowerShell
    }
}

#[cfg(target_os = "macos")]
impl Default for ShellOption {
    fn default() -> Self {
        Self::Zsh
    }
}
