# PMDL
Simple cli password manager that stores an encrypted database in the appdata folder. It's very ugly (in terms of code and interface) but a working prototype. Made for fun

![My Image](demo.gif)

## Configuration
1) Open this project, open file functions.rs and do a search using Ctrl + F. Search for the line `//#changemedb`. Find all the lines with these marks and write your encryption keys (explanations are written in the comments in the code)
2) Next, find `//#changemepassword`
3) After that, in the main.rs, comment out all the functions in main() and add `use pmdl::functions::functions::first_db_creation;`
4) Write the `first_db_creation();` function in main()
5) Run `cargo r`. This will create an encrypted version of the database and delete the old one
6) Now remove the `first_db_creation();` from main() and uncomment the old functions
7) Run `cargo b --release`
8) Place the encrypted database file that you created earlier in the folder where the compiled exe file of the application is located (`.\target\release\`)
9) Run pmdl.exe

## Database dump

This script assumes saving the database in a telegram bot. Create a bot in @BotFather, copy the bot token to a dump.py. Find your user id/chat id (this is done very simply) and copy it to dump.py. Place a dump.py is next to pmdl.exe. And of course you can use dump.py without a password manager application, if you edit the code a little. (after all, it's just a python script)