use crate::pages::pages::*;
use crate::*;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rusqlite::Connection;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::{env, io};
use winapi::um::winnt::FILE_ATTRIBUTE_HIDDEN;

use std::cmp::Ordering;

use std::fs;
use std::path::Path;
use std::process::Command;

use win32console::console::{ConsoleTextAttribute, WinConsole};

use bcrypt::{hash, hash_with_salt, verify, Version};

use std::thread::sleep;
use std::time::Duration;

pub fn print_banner() {
    println!(
        r" _____                                    _    __  __                                          _ _                _       _                "
    );
    println!(
        r"|  __ \                                  | |  |  \/  |                                        | | |              | |     | |               "
    );
    println!(
        r"| |__) |_ _ ___ _____      _____  _ __ __| |  | \  / | __ _ _ __   __ _  __ _  ___ _ __     __| | |_   _  __ _   | | ___ | |__   _____   __"
    );
    println!(
        r"|  ___/ _` / __/ __\ \ /\ / / _ \| '__/ _` |  | |\/| |/ _` | '_ \ / _` |/ _` |/ _ \ '__|   / _` | | | | |/ _` |  | |/ _ \| '_ \ / _ \ \ / /"
    );
    println!(
        r"| |  | (_| \__ \__ \\ V  V / (_) | | | (_| |  | |  | | (_| | | | | (_| | (_| |  __/ |     | (_| | | |_| | (_| |  | | (_) | | | | (_) \ V / "
    );
    println!(
        r"|_|   \__,_|___/___/ \_/\_/ \___/|_|  \__,_|  |_|  |_|\__,_|_| |_|\__,_|\__, |\___|_|      \__,_|_|\__, |\__,_|  |_|\___/|_| |_|\___/ \_/  "
    );
    println!(
        r"                                                                         __/ |                      __/ |                                 "
    );
    println!(
        r"                                                                        |___/                      |___/                                  "
    );
    println!();
}

pub fn print_banner_small() {
    println!(r",------. ,--.   ,--.,------.  ,--.    ");
    println!(r"|  .--. '|   `.'   ||  .-.  \ |  |    ");
    println!(r"|  '--' ||  |'.'|  ||  |  \  :|  |    ");
    println!(r"|  | --' |  |   |  ||  '--'  /|  '--. ");
    println!(r"`--'     `--'   `--'`-------' `-----' ");
    println!();
}

pub fn pause_between_screens() {
    let time = Duration::from_millis(1600);
    sleep(time);
}

pub fn command_prompt() {
    show_name();
    let _ = io::stdout().flush();
    let mut varikk = String::new();
    io::stdin()
        .read_line(&mut varikk)
        .expect("Failed to read line");
    command_handling(&varikk);
}

pub fn check_user_exists(name: &str) -> bool {
    struct UserCheck {
        login: String,
    }
    decrypt_db();
    let db = get_storage_dir() + "/c35312fb3a7e05.db";
    let conn = Connection::open(db).unwrap();
    let mut check = false;
    let sql = format!("SELECT login FROM users WHERE login = '{}';", name);
    {
        let mut stmt = conn.prepare(&sql).unwrap();
        let person_iter = stmt
            .query_map([], |row| {
                Ok(UserCheck {
                    login: row.get(0).unwrap(),
                })
            })
            .unwrap();

        for _person in person_iter {
            check = true;
        }
    }
    conn.close().unwrap();
    encrypt_db_select();
    check
}

pub fn login_user(ar: &[String; 2]) -> [i32; 2] {
    struct LoginCheck {
        id: i32,
        password: String,
    }
    decrypt_db();
    let db = get_storage_dir() + "/c35312fb3a7e05.db";
    let conn = Connection::open(db).unwrap();
    let mut check = [0, 0];
    let sql = format!(
        "SELECT id, password FROM users WHERE login = '{}';",
        &ar[0].trim()
    );
    {
        let mut stmt = conn.prepare(&sql).unwrap();
        let person_iter = stmt
            .query_map([], |row| {
                Ok(LoginCheck {
                    id: row.get(0).unwrap(),
                    password: row.get(1).unwrap(),
                })
            })
            .unwrap();

        for person in person_iter {
            match person {
                Ok(k) => {
                    let valid = verify(&ar[1], &k.password).unwrap();
                    if valid {
                        check[0] = 1;
                        check[1] = k.id;
                    }
                }
                Err(_e) => (),
            };
        }
    }
    conn.close().unwrap();
    encrypt_db_select();

    check
}

pub fn register_user(ar: &[String; 3]) -> String {
    decrypt_db();
    let db = get_storage_dir() + "/c35312fb3a7e05.db";
    let conn = Connection::open(db).unwrap();
    let sql = format!(
        "INSERT INTO users (login, password) VALUES ('{}', '{}');",
        ar[0].trim(),
        hash(&ar[1], 15).unwrap()
    );
    conn.execute(&sql, ()).unwrap();
    let id = conn.last_insert_rowid().to_string();
    conn.close().unwrap();
    encrypt_db_insert();

    id
}

////////////////////////////////////
pub fn first_db_creation() {
    let dbkey: &[u8] = &[ //#changemedb
        0,0 //write 32 random numbers here (0-255)
    ];
    let dbkey: &Key<Aes256Gcm> = dbkey.into();
    let dbcipher = Aes256Gcm::new(dbkey);
    let dbnonce: &aes_gcm::aead::generic_array::GenericArray<
        u8,
        aes_gcm::aes::cipher::typenum::UInt<
            aes_gcm::aes::cipher::typenum::UInt<
                aes_gcm::aes::cipher::typenum::UInt<
                    aes_gcm::aes::cipher::typenum::UInt<
                        aes_gcm::aes::cipher::typenum::UTerm,
                        aes_gcm::aead::consts::B1,
                    >,
                    aes_gcm::aead::consts::B1,
                >,
                aes_gcm::aead::consts::B0,
            >,
            aes_gcm::aead::consts::B0,
        >,
    > = Nonce::from_slice(b"00a"); //#changemedb //write 12 random characters

    let encrypt_db = "./c35312fb3a7e05.db";
    let encrypt_byte_content = fs::read(encrypt_db).unwrap();
    let encrypt_ciphertext: Vec<u8> = dbcipher
        .encrypt(dbnonce, encrypt_byte_content.as_ref())
        .unwrap();
    let mut encrypt_file = OpenOptions::new()
        .write(true)
        .create(true)
        .attributes(FILE_ATTRIBUTE_HIDDEN)
        .open("./ec35312fb3a7e05.db")
        .unwrap();
    encrypt_file.write_all(&encrypt_ciphertext);
    fs::remove_file("./c35312fb3a7e05.db");
    std::process::exit(0);
}
////////////////////////////////////

pub fn decrypt_db() {
    let dbkey: &[u8] = &[ //#changemedb
        0,0 //write 32 random numbers here (0-255). they should be the same as in first_db_creation()
    ];
    let dbkey: &Key<Aes256Gcm> = dbkey.into();
    let dbcipher = Aes256Gcm::new(dbkey);
    let dbnonce: &aes_gcm::aead::generic_array::GenericArray<
        u8,
        aes_gcm::aes::cipher::typenum::UInt<
            aes_gcm::aes::cipher::typenum::UInt<
                aes_gcm::aes::cipher::typenum::UInt<
                    aes_gcm::aes::cipher::typenum::UInt<
                        aes_gcm::aes::cipher::typenum::UTerm,
                        aes_gcm::aead::consts::B1,
                    >,
                    aes_gcm::aead::consts::B1,
                >,
                aes_gcm::aead::consts::B0,
            >,
            aes_gcm::aead::consts::B0,
        >,
    > = Nonce::from_slice(b"00a"); //#changemedb //write 12 random characters. they should be the same as in first_db_creation()

    let decrypt_db = get_storage_dir() + "/ec35312fb3a7e05.db";
    let decrypt_byte_content = fs::read(decrypt_db).unwrap();
    let decrypt_ciphertext: Vec<u8> = dbcipher
        .decrypt(dbnonce, decrypt_byte_content.as_ref())
        .unwrap();

    let mut decrypt_file = OpenOptions::new()
        .write(true)
        .create(true)
        .attributes(FILE_ATTRIBUTE_HIDDEN)
        .open(get_storage_dir() + "/c35312fb3a7e05.db")
        .unwrap();
    decrypt_file.write_all(&decrypt_ciphertext);
}

pub fn encrypt_db_select() {
    fs::remove_file(get_storage_dir() + "/c35312fb3a7e05.db");
}

pub fn encrypt_db_insert() {
    let dbkey: &[u8] = &[ //#changemedb
        0,0 //write 32 random numbers here (0-255). they should be the same as in first_db_creation()
    ];
    let dbkey: &Key<Aes256Gcm> = dbkey.into();
    let dbcipher = Aes256Gcm::new(dbkey);
    let dbnonce: &aes_gcm::aead::generic_array::GenericArray<
        u8,
        aes_gcm::aes::cipher::typenum::UInt<
            aes_gcm::aes::cipher::typenum::UInt<
                aes_gcm::aes::cipher::typenum::UInt<
                    aes_gcm::aes::cipher::typenum::UInt<
                        aes_gcm::aes::cipher::typenum::UTerm,
                        aes_gcm::aead::consts::B1,
                    >,
                    aes_gcm::aead::consts::B1,
                >,
                aes_gcm::aead::consts::B0,
            >,
            aes_gcm::aead::consts::B0,
        >,
    > = Nonce::from_slice(b"00a"); //#changemedb //write 12 random characters. they should be the same as in first_db_creation()
    
    let encrypt_db = get_storage_dir() + "/c35312fb3a7e05.db";
    let encrypt_byte_content = fs::read(encrypt_db).unwrap();
    let encrypt_ciphertext: Vec<u8> = dbcipher
        .encrypt(dbnonce, encrypt_byte_content.as_ref())
        .unwrap();
    let mut encrypt_file = OpenOptions::new()
        .write(true)
        .create(true)
        .attributes(FILE_ATTRIBUTE_HIDDEN)
        .open(get_storage_dir() + "/ec35312fb3a7e05.db")
        .unwrap();
    encrypt_file.write_all(&encrypt_ciphertext);
    fs::remove_file(get_storage_dir() + "/c35312fb3a7e05.db");
}

pub fn insert_passwords(ar: &[String; 2]) {
    unsafe {
        let key: &[u8] = &[ //#changemepassword encrypting the logins and passwords you entered
            0, 0 //write 32 random numbers here (0-255).
        ];
        let key: &Key<Aes256Gcm> = key.into();
        let cipher = Aes256Gcm::new(key);

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let txt = format!("{} — {}", ar[0].trim(), ar[1].trim());

        let ciphertext: Vec<u8> = cipher.encrypt(&nonce, txt.as_ref()).unwrap();
        let mut hex = String::from("");
        for x in &ciphertext {
            hex.push_str(format!(" {:x}", x).as_str());
        }
        hex.push(' ');
        decrypt_db();
        let db = get_storage_dir() + "/c35312fb3a7e05.db";
        let conn = Connection::open(db).unwrap();
        let sql = format!(
            "INSERT INTO passwords (nonce, user_id, user_data) VALUES ('{}', {}, '{}');",
            format!("{:x}", &nonce), //format in format
            SESSION_USER[1],
            format!("{}", hex)
        );
        conn.execute(&sql, ()).unwrap();
        vector_passwords();
        conn.close().unwrap();
        encrypt_db_insert();
    }
}

pub fn help() {
    println!();
    println!("/home - back to start page");
    println!("/lo - log out");
    println!("/menu - print user menu");
    println!("/del %password_id% - delete password from your list with specified ID");
    println!("/cp %password_id% - copy the password from your list with the specified ID to the clipboard");
    println!(
        "* Logins and passwords cannot begin with slashes (/). Only commands begin with slashes"
    );
    println!("* commands can be entered even while entering the password (when the text is not displayed when printing)");
    println!("PMDL v0.1.1 22.02.2024 by KATAMARANOV (C)");
}

pub fn vector_passwords() {
    struct Passwords {
        id: i32,
    }
    unsafe {
        DELETION = Default::default();
        let mut counter: u8 = 0;
        let db = get_storage_dir() + "/c35312fb3a7e05.db";
        let conn = Connection::open(db).unwrap();
        let sql = format!(
            "SELECT id FROM passwords WHERE user_id = {};",
            SESSION_USER[1]
        );
        {
            let mut stmt = conn.prepare(&sql).unwrap();
            let person_iter = stmt
                .query_map([], |row| {
                    Ok(Passwords {
                        id: row.get(0).unwrap(),
                    })
                })
                .unwrap();
            for person in person_iter {
                match person {
                    Ok(k) => {
                        counter += 1;
                        DELETION.push(counter);
                        DELETION.push(k.id as u8);
                    }
                    Err(_e) => (),
                };
            }
        }
        conn.close().unwrap();
    }
}

pub fn show_passwords() {
    struct Passwords {
        id: i32,
        nonce: String,
        user_data: String,
    }
    unsafe {
        DELETION = Default::default();
        decrypt_db();
        let mut counter: u8 = 0;
        let db = get_storage_dir() + "/c35312fb3a7e05.db";
        let conn = Connection::open(db).unwrap();
        let sql = format!(
            "SELECT id, nonce, user_data FROM passwords WHERE user_id = {};",
            SESSION_USER[1]
        );
        {
            let mut stmt = conn.prepare(&sql).unwrap();
            let person_iter = stmt
                .query_map([], |row| {
                    Ok(Passwords {
                        id: row.get(0).unwrap(),
                        nonce: row.get(1).unwrap(),
                        user_data: row.get(2).unwrap(),
                    })
                })
                .unwrap();
            for person in person_iter {
                match person {
                    Ok(k) => {
                        counter += 1;
                        DELETION.push(counter);
                        DELETION.push(k.id as u8);

                        let key: &[u8] = &[ //#changemepassword encrypting the logins and passwords you entered
                            0,0 //write 32 random numbers here (0-255). it should be the same as in insert_passwords()
                        ];
                        let key: &Key<Aes256Gcm> = key.into();
                        let cipher = Aes256Gcm::new(key);

                        let mut empty_vec: Vec<u8> = vec![];
                        let decoded = hex::decode(k.nonce).expect("Decoding failed");
                        let nnonce: &aes_gcm::aead::generic_array::GenericArray<
                            u8,
                            aes_gcm::aes::cipher::typenum::UInt<
                                aes_gcm::aes::cipher::typenum::UInt<
                                    aes_gcm::aes::cipher::typenum::UInt<
                                        aes_gcm::aes::cipher::typenum::UInt<
                                            aes_gcm::aes::cipher::typenum::UTerm,
                                            aes_gcm::aead::consts::B1,
                                        >,
                                        aes_gcm::aead::consts::B1,
                                    >,
                                    aes_gcm::aead::consts::B0,
                                >,
                                aes_gcm::aead::consts::B0,
                            >,
                        > = Nonce::from_slice(&decoded);
                        for capture in k.user_data.split(' ') {
                            let bb = capture;
                            if bb.is_empty() {
                            } else if bb.len() == 1 {
                                let a2: u8 = match bb {
                                    "0" => 0,
                                    "1" => 1,
                                    "2" => 2,
                                    "3" => 3,
                                    "4" => 4,
                                    "5" => 5,
                                    "6" => 6,
                                    "7" => 7,
                                    "8" => 8,
                                    "9" => 9,
                                    "a" => 10,
                                    "b" => 11,
                                    "c" => 12,
                                    "d" => 13,
                                    "e" => 14,
                                    "f" => 15,
                                    _ => panic!("nope"),
                                };
                                empty_vec.push(a2);
                            } else if bb.len() == 2 {
                                let a = hex::decode(capture).expect("Decoding failed");
                                empty_vec.push(a[0]);
                            }
                        }
                        let dec = cipher.decrypt(nnonce, empty_vec.as_ref()).unwrap();
                        println!();
                        println!(
                            "\x1b[91m{}.\x1b[37m\x1b[1m {}",
                            counter,
                            std::str::from_utf8(&dec).unwrap()
                        );
                    }
                    Err(_e) => (),
                };
            }
        }
        conn.close().unwrap();
        encrypt_db_select();
        command_prompt();
    }
}

pub fn command_not_found() {
    unsafe {
        println!("Command not found!");
        match CURRENT_LOCATION {
            1 => {
                pause_between_screens();
                start_page();
            }
            2 => {
                pause_between_screens();
                register();
            }
            3 => {
                pause_between_screens();
                login();
            }
            4 => {
                pause_between_screens();
                menu();
            }
            5 => {
                pause_between_screens();
                create_passwords();
            }
            _ => (),
        };
    }
}

pub fn command_handling(arg: &str) {
    match arg.trim() {
        "/s" => unsafe {
            if !SESSION_USER.is_empty() {
                //not empty = signed in
                println!("Already signed up");
                match CURRENT_LOCATION {
                    1 => {
                        pause_between_screens();
                        start_page();
                    }
                    4 => {
                        pause_between_screens();
                        menu();
                    }
                    5 => {
                        pause_between_screens();
                        create_passwords();
                    }
                    _ => (),
                };
            } else if CURRENT_LOCATION == 2 {
                println!("Already on register page");
                pause_between_screens();
            } else {
                register();
            }
        },
        "/1" => unsafe {
            if CURRENT_LOCATION != 4 {
                command_not_found();
            } else {
                create_passwords();
            }
        },
        "/2" => unsafe {
            if CURRENT_LOCATION != 4 {
                command_not_found();
            } else {
                show_passwords();
            }
        },
        "/help" => unsafe {
            match CURRENT_LOCATION {
                2 => 'inner: {
                    HELP_WINDOW = 1;
                    break 'inner;
                }
                3 => 'inner: {
                    HELP_WINDOW = 1;
                    break 'inner;
                }
                5 => 'inner: {
                    HELP_WINDOW = 1;
                    break 'inner;
                }
                _ => {
                    help();
                    command_prompt();
                }
            }
        },
        "/l" => unsafe {
            if !SESSION_USER.is_empty() {
                println!("Already signed in");
                match CURRENT_LOCATION {
                    1 => {
                        pause_between_screens();
                        start_page();
                    }
                    4 => {
                        pause_between_screens();
                        menu();
                    }
                    5 => {
                        pause_between_screens();
                        create_passwords();
                    }
                    _ => (),
                };
            } else if CURRENT_LOCATION == 3 {
                println!("Already on login page");
                pause_between_screens();
            } else {
                login();
            }
        },
        "/lo" => {
            unsafe {
                SESSION_USER = Default::default();
                DELETION = Default::default();
            }
            start_page();
        }
        "/menu" => unsafe {
            if !SESSION_USER.is_empty() {
                if CURRENT_LOCATION == 4 {
                    println!("Already on menu page");
                    pause_between_screens();
                    menu();
                } else {
                    menu();
                }
            } else {
                println!("first you need to register or log in");
                match CURRENT_LOCATION {
                    1 => {
                        pause_between_screens();
                        start_page();
                    }
                    2 => {
                        pause_between_screens();
                        register();
                    }
                    3 => {
                        pause_between_screens();
                        login();
                    }
                    _ => (),
                };
            }
        },
        "/home" => unsafe {
            if CURRENT_LOCATION == 1 {
                println!("Already on a home page");
                pause_between_screens();
                start_page();
            } else {
                start_page();
            }
        },
        "/exit" => {
            print!("\x1b[0m");
            Command::new("cmd")
                .args(["/c", "cls"])
                .spawn()
                .expect("cls command failed to start")
                .wait()
                .expect("failed to wait");
            std::process::exit(0)
        }
        _ => {
            if arg.trim().contains("/del") {
                unsafe {
                    if CURRENT_LOCATION != 4 {
                        command_not_found();
                    }
                    let mut id = String::from("");
                    match arg.trim().len() {
                        6 => {
                            let cnt = arg.trim().chars().last().unwrap().to_string();

                            let c = DELETION.len();

                            let mut s = 1;
                            let mut nothingfound = 0;

                            for x in &DELETION {
                                if s % 2 != 0 {
                                    if cnt == x.to_string() {
                                        id = DELETION[s].to_string();
                                        decrypt_db();
                                        let db = get_storage_dir() + "/c35312fb3a7e05.db";
                                        let conn = Connection::open(db).unwrap();
                                        let sql =
                                            format!("DELETE FROM passwords WHERE id = {}", id);
                                        conn.execute(&sql, ()).unwrap();
                                        vector_passwords();
                                        println!();
                                        println!("Removed password №{}", cnt);
                                        conn.close().unwrap();
                                        encrypt_db_insert(); //переименовать инсерт в changes
                                    } else if cnt != x.to_string() {
                                        nothingfound += 1;
                                    }
                                }
                                s += 1;
                            }

                            if nothingfound == c / 2 {
                                println!();
                                println!("Error! nothing was found with the specified ID");
                                command_prompt();
                            }

                            command_prompt();
                        }
                        7 => {
                            //let cnt = arg.trim().chars().rev().take(2).collect();
                            let cnt = arg.trim().as_bytes();
                            let mut mas = String::from("");
                            let len = cnt.len();
                            if cnt[len - 2] != 32 {
                                mas = std::str::from_utf8(&[cnt[len - 2]]).unwrap().to_owned()
                                    + std::str::from_utf8(&[cnt[len - 1]]).unwrap();
                            } else {
                                mas = "".to_owned() + std::str::from_utf8(&[cnt[len - 1]]).unwrap();
                            }

                            let c = DELETION.len();
                            let mut s = 1;
                            let mut nothingfound = 0;

                            for x in &DELETION {
                                if s % 2 != 0 {
                                    if mas == x.to_string() {
                                        id = DELETION[s].to_string();
                                        decrypt_db();
                                        let db = get_storage_dir() + "/c35312fb3a7e05.db";
                                        let conn = Connection::open(db).unwrap();
                                        let sql =
                                            format!("DELETE FROM passwords WHERE id = {}", id);
                                        conn.execute(&sql, ()).unwrap();
                                        vector_passwords();
                                        println!();
                                        println!("Removed password №{}", mas);
                                        conn.close().unwrap();
                                        encrypt_db_insert();
                                    } else if mas != x.to_string() {
                                        nothingfound += 1;
                                    }
                                }
                                s += 1;
                            }

                            if nothingfound == c / 2 {
                                println!();
                                println!("Error! nothing was found with the specified ID");
                                command_prompt();
                            }

                            command_prompt();
                        }
                        _ => command_not_found(),
                    }
                }
            } else {
                command_not_found();
            }
        }
    }
}

pub fn update_screen() {
    let old_info = WinConsole::output().get_screen_buffer_info_ex().unwrap();
    let width = format!("{:#?}", old_info.screen_buffer_size.x);
    let size: u16 = width.trim().parse().unwrap();
    Command::new("cmd")
        .args(["/c", "cls"])
        .spawn()
        .expect("cls command failed to start")
        .wait()
        .expect("failed to wait");

    match size.cmp(&200) {
        Ordering::Less => print_banner_small(),
        Ordering::Greater => print_banner(),
        Ordering::Equal => (),
    }
}

pub fn get_storage_dir() -> String {
    let temp_name = env::var("username").unwrap();

    let mut dir_name = String::from("Temp-");

    let hashed = hash_with_salt(
        temp_name,
        12,
        [
            255, 9, 74, 91, 100, 64, 3, 199, 0, 173, 222, 66, 13, 192, 51, 1,
        ],
    )
    .unwrap();

    dir_name.push_str(hashed.format_for_version(Version::TwoA).as_str());

    let home_dir = env::var("userprofile").unwrap();
    let dir: String = "/AppData/Local/".to_string();

    home_dir + &dir + &dir_name // юзать path join
}

pub fn init() {
    fs::create_dir_all(get_storage_dir()).unwrap();
    Command::new("cmd")
        .args(["/c", "color 17"])
        .spawn()
        .expect("cls command failed to start")
        .wait()
        .expect("failed to wait");
    print!("\x1b[1m");
    let b = Path::new("ec35312fb3a7e05.db").is_file();
    match b {
        true => {
            fs::copy(
                "./ec35312fb3a7e05.db",
                get_storage_dir() + "/ec35312fb3a7e05.db",
            );
            fs::remove_file("ec35312fb3a7e05.db");
        }
        false => {}
    }
}

pub fn show_name() {
    println!();
    unsafe {
        if SESSION_USER.is_empty() {
            let old_attributes = WinConsole::output().get_text_attribute().unwrap();
            let new_attributes = ConsoleTextAttribute::BACKGROUND_RED;
            WinConsole::output().write_utf8("V 0.1.1 ".as_bytes());
            WinConsole::output().set_text_attribute(new_attributes);
            WinConsole::output().write_utf8("Not in account >".as_bytes());
            WinConsole::output().set_text_attribute(old_attributes);
            print!(" ");
        } else {
            print!("V 0.1.1, {} > ", SESSION_USER[0]);
        }
    }
}

pub fn draw_menu() {
    let old_attributes = WinConsole::output().get_text_attribute().unwrap();
    let new_attributes = ConsoleTextAttribute::FOREGROUND_RED;
    WinConsole::output().set_text_attribute(new_attributes);
    let a = "╔═══════════════════════════════════╗"
        .encode_utf16()
        .collect::<Vec<u16>>();
    let b = "║                                   ║"
        .encode_utf16()
        .collect::<Vec<u16>>();
    let c = "║        /1 Create Password         ║"
        .encode_utf16()
        .collect::<Vec<u16>>();
    let d = "║        /2 Show passwords          ║"
        .encode_utf16()
        .collect::<Vec<u16>>();
    let e = "║        /3 Settings                ║"
        .encode_utf16()
        .collect::<Vec<u16>>();
    let f = "║        /del %password_id%         ║"
        .encode_utf16()
        .collect::<Vec<u16>>();
    let ff = "║        /cp %password_id%          ║"
        .encode_utf16()
        .collect::<Vec<u16>>();
    let g = "║                                   ║"
        .encode_utf16()
        .collect::<Vec<u16>>();
    let h = "║                                   ║"
        .encode_utf16()
        .collect::<Vec<u16>>();
    let i = "╚═══════════════════════════════════╝"
        .encode_utf16()
        .collect::<Vec<u16>>();
    WinConsole::output().write_utf16(a.as_slice());
    println!();
    WinConsole::output().write_utf16(b.as_slice());
    println!();
    WinConsole::output().write_utf16(c.as_slice());
    println!();
    WinConsole::output().write_utf16(d.as_slice());
    println!();
    WinConsole::output().write_utf16(e.as_slice());
    println!();
    WinConsole::output().write_utf16(f.as_slice());
    println!();
    WinConsole::output().write_utf16(ff.as_slice());
    println!();
    WinConsole::output().write_utf16(g.as_slice());
    println!();
    WinConsole::output().write_utf16(h.as_slice());
    println!();
    WinConsole::output().write_utf16(i.as_slice());
    println!();
    WinConsole::output().set_text_attribute(old_attributes);
    println!();
}
