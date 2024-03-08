use crate::functions::functions::*;
use crate::*;

use rpassword;
use std::io;

pub fn register() {
    unsafe { CURRENT_LOCATION = 2 }

    let phrases: [&str; 3] = [
        "Create your login: ",
        "Create your password (will not be echoed): ",
        "Repeat password (will not be echoed):",
    ];
    let mut vars: [String; 3] = Default::default();

    'outer: loop {
        for l in &vars {
            if !l.is_empty() && l.starts_with('/') {
                command_handling(l);
            }
        }

        vars = Default::default();
        'inner: for (i, v) in phrases.into_iter().enumerate() {
            update_screen();
            unsafe {
                if HELP_WINDOW != 0 {
                    HELP_WINDOW = 0;
                    help();
                    println!();
                }
            }
            println!("\x1b[91m\x1b[40mLogins and passwords cannot begin with slashes (/). Only commands begin with slashes\x1b[37m\x1b[44m\x1b[1m");
            println!();
            println!("{v}");

            if i != 0 {
                vars[i] = rpassword::read_password().unwrap();
                if vars[i].is_empty() {
                    println!("Error! The password should not be empty.");
                    pause_between_screens();
                    break 'inner;
                }
                if vars[i].starts_with('/') {
                    break 'inner;
                }
            } else {
                io::stdin()
                    .read_line(&mut vars[i])
                    .expect("Failed to read line");
                if vars[0].chars().next().as_slice() == ['\r'] {
                    println!("Error! The name should not be empty.");
                    pause_between_screens();
                    break 'inner;
                }
                if vars[0].starts_with('/') {
                    break 'inner;
                }
                ///////////

                match check_user_exists(vars[0].trim()) {
                    true => {
                        println!("Error! Account with this name already exists.");
                        pause_between_screens();
                        break 'inner;
                    }
                    false => {}
                };
            }

            if i == 2 && vars[1] != vars[2] {
                println!("Error! Passwords do not match. Try again...");
                pause_between_screens();
            } else if i == 2 && vars[1] == vars[2] {
                break 'outer;
            }
        }
    }

    let gg = vars[0].clone();
    let id = register_user(&vars);
    unsafe {
        SESSION_USER.push(gg.trim().to_string());
        SESSION_USER.push(id);
    }
    menu();
}

pub fn login() {
    unsafe { CURRENT_LOCATION = 3 }
    let phrases: [&str; 2] = [
        "Enter your login: ",
        "Enter your password (will not be echoed): ",
    ];
    let mut tmp: [i32; 2] = Default::default();
    let mut vars: [String; 2] = Default::default();

    'outer: loop {
        for l in &vars {
            if !l.is_empty() && l.starts_with('/') {
                command_handling(l);
            }
        }

        vars = Default::default();
        'inner: for (i, v) in phrases.into_iter().enumerate() {
            update_screen();
            unsafe {
                if HELP_WINDOW != 0 {
                    HELP_WINDOW = 0;
                    help();
                    println!();
                }
            }
            println!("{v}");
            if i == 0 {
                io::stdin()
                    .read_line(&mut vars[i])
                    .expect("Failed to read line");
                if vars[0].chars().next().as_slice() == ['\r'] {
                    //тут тоже попробовать trim()
                    println!("Error! The login should not be empty.");
                    pause_between_screens();
                    break 'inner;
                }
                if vars[0].trim().starts_with('/') {
                    break 'inner;
                }
            } else {
                vars[1] = rpassword::read_password().unwrap();
                if vars[1].is_empty() {
                    println!("Error! The password should not be empty.");
                    pause_between_screens();
                    break 'inner;
                }
                if vars[1].starts_with('/') {
                    break 'inner;
                }
            }
            if i == 1 {
                let check = login_user(&vars);
                if check[0] == 0 {
                    println!("Error! invalid login or password.");
                    pause_between_screens();
                    break 'inner;
                } else if check[0] == 1 {
                    tmp = check;
                    break 'outer;
                }
            }
        }
    }

    let gg = vars[0].clone();
    unsafe {
        SESSION_USER.push(gg.trim().to_string());
        SESSION_USER.push(tmp[1].to_string());
    }
    menu();
}

pub fn create_passwords() {
    unsafe { CURRENT_LOCATION = 5 }
    let phrases: [&str; 2] = ["Enter description: ", "Enter password: "];
    let mut vars: [String; 2] = Default::default();

    'outer: loop {
        for l in &vars {
            if !l.is_empty() && l.starts_with('/') {
                command_handling(l);
            }
        }

        vars = Default::default();
        'inner: for (i, v) in phrases.into_iter().enumerate() {
            update_screen();
            unsafe {
                if HELP_WINDOW != 0 {
                    HELP_WINDOW = 0;
                    help();
                    println!();
                }
            }
            println!("\x1b[91m\x1b[40mDescription and passwords cannot begin with slashes (/). Only commands begin with slashes\x1b[37m\x1b[44m\x1b[1m");
            println!();
            println!("{v}");
            if i == 0 {
                io::stdin()
                    .read_line(&mut vars[i])
                    .expect("Failed to read line");
                if vars[0].chars().next().as_slice() == ['\r'] {
                    println!("Error! The description should not be empty.");
                    pause_between_screens();
                    break 'inner;
                }
                if vars[0].starts_with('/') {
                    break 'inner;
                }
            } else {
                io::stdin()
                    .read_line(&mut vars[1])
                    .expect("Failed to read line");
                if vars[1].chars().next().as_slice() == ['\r'] {
                    println!("Error! The password should not be empty.");
                    pause_between_screens();
                    break 'inner;
                }
                if vars[1].starts_with('/') {
                    break 'inner;
                }
            }

            if i == 1 {
                insert_passwords(&vars);
                break 'outer;
            }
        }
    }
    menu();
}

pub fn menu() {
    unsafe { CURRENT_LOCATION = 4 }
    update_screen();
    unsafe {
        if FIRST_LOGIN == 1 {
            decrypt_db();
            vector_passwords();
            encrypt_db_select();
            FIRST_LOGIN = 0;
        }
    }
    draw_menu();
    command_prompt();
}

pub fn start_page() {
    unsafe {
        CURRENT_LOCATION = 1;
        if !SESSION_USER.is_empty() {
            update_screen();
            print!("Show Menu(/menu)\t\t");
            print!("Help(/help)\t\t");
            println!("Log Out(/lo)");
        } else {
            update_screen();
            print!("\t\t\tLog In(/l)\t\t");
            print!("Help(/help)\t\t");
            println!("Sign Up(/s)");
        }
    }
    command_prompt();
}
