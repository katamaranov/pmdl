# PMDL
Simple cli password manager that stores an encrypted database in the %APPDATA% folder. It's very ugly (in terms of code and interface) but a working prototype. Made for fun

![My Image](demo.gif)

## Configuration
1) Open the project, open file functions.rs and do a search using Ctrl + F. Search for the line `//#changemedb`. Find all the lines with these marks and write your encryption key (explanations are written in the comments in the code)
2) Next, find `//#changemepassword`
3) After that, in the main.rs, comment out all the functions in main()
4) Write the `first_db_creation();` function in main()
5) Run `cargo r`. This will create an encrypted version of the database and delete the old one. (The created file has a `hidden` attribute)
6) Now remove the `first_db_creation();` from main() and uncomment the old functions
7) Run `cargo b --release`
8) Place the encrypted database file that you created earlier in the folder where the compiled exe file of the application is located (`.\target\release\`)
9) Run pmdl.exe
