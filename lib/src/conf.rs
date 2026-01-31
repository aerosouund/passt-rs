use serde::{Deserialize, Serialize};

#[derive(Default)]
pub struct Conf {
    pub tap_fd: i32,
    pub mode: Mode,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Passt,
    Pasta,
}
