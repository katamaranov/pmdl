pub mod functions;
pub mod pages;

pub static mut SESSION_USER: Vec<String> = vec![];
pub static mut DELETION: Vec<u8> = vec![];
pub static mut CURRENT_LOCATION: i8 = 0;
pub static mut FIRST_LOGIN: i8 = 1;
pub static mut HELP_WINDOW: i8 = 0;
