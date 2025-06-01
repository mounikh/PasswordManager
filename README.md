Overview
Password Manager GUI is a Java desktop application designed to securely store, manage, and retrieve user credentials (site, username, and password). It uses AES encryption with CBC mode and PBKDF2 for key derivation to encrypt passwords before saving them in an SQLite database. The application features a user-friendly Swing-based graphical interface.

Features
Master Password Protection: Unlock the database with a master password that protects all stored credentials.

AES Encryption (AES/CBC/PKCS5Padding): Passwords are encrypted using AES with a unique salt and initialization vector (IV) for each entry.

SQLite Database Storage: All credentials are stored securely in an SQLite database file (passwords.db).

Add Credentials: Save new site, username, and password entries.

Search Credentials: Search saved credentials by site name.

View All Credentials: Display all stored credentials in a table.

Delete Credentials: Remove selected entries from the database.

Secure Key Derivation: Uses PBKDF2WithHmacSHA256 with 65,536 iterations and 256-bit key size for deriving encryption keys from the master password.

GUI Interface: Easy to use, built with Java Swing.

Technologies Used
Java SE (Swing for GUI)

Java Cryptography Architecture (JCA)

SQLite (via JDBC)

AES encryption with CBC mode

PBKDF2 for password-based key derivation

Requirements
Java 8 or higher

SQLite JDBC Driver (included in most JDKs or can be added manually)

Write permissions in the working directory to create and update passwords.db

How to Run
Compile the code
Make sure you have the Java compiler installed.

bash
Copy
Edit
javac PasswordManagerGUI.java
Run the application

bash
Copy
Edit
java PasswordManagerGUI
Using the application

On startup, enter a master password and click Unlock.

If this is your first time, you can use any master password to initialize the database.

Add new credentials by filling the "Site", "Username", and "Password" fields and clicking Add Credential.

Use the search box to find credentials by site name.

Select a credential in the table to delete it.

Use Show All to display all saved credentials.

Security Notes
Each password entry is encrypted with AES using a unique salt and IV.

The master password is used to derive the AES encryption key with PBKDF2.

The master password salt is fixed for demo purposes ("MasterSalt123456"), but for production usage, it should be securely generated and stored.

Passwords are decrypted in-memory only when displayed and never stored or transmitted in plaintext.

The database file passwords.db stores only encrypted passwords along with their salts and IVs.

Code Structure
PasswordManagerGUI.java: Main application class with GUI, encryption/decryption logic, and database operations.

GUI Components: Swing components for input fields, buttons, and a JTable for displaying credentials.

Encryption/Decryption: Uses AES/CBC/PKCS5Padding with keys derived by PBKDF2.

Database: Uses SQLite for storing encrypted credentials with fields: id, site, username, salt, iv, and encrypted password.

Limitations & Future Improvements
Currently, the master password salt is hardcoded — consider storing it securely or generating dynamically.

Passwords are displayed in plaintext in the table after decrypting; consider masking or adding a "show/hide" toggle.

Add password strength validation.

Improve master password verification (currently it tries to decrypt the first entry).

Add export/import functionality for backup.

Implement better error handling and input validation.

