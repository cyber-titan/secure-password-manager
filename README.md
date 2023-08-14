# Secure Password Manager

Secure password manager is capable of storing multiple users passwords securely in SQLite3 database. It stores all the users passwords in encrypted form, this is done by using fernet module. Only when displaying the passwords, the passwords will be visible in plaintext. You just need to remember one password i.e., the master password. A key will be derived from the master password (which you will use for logging into your account, if you don't have one you can create one and set a master password) which will be used to: 
a) encrypt the master password by deriving a key from the master password itself and then using the derived key to encrypt the master password and store it and then store the encrypted master password.
b) encrypt/decrypt stored passwords in database (it maybe master password (or) other passwords of accounts which user stores).

This derived key will always be same is correct master password is entered as I am using pbkdf2 (Password Based Key Derivation Function 2) in hashlib module. If wrong password is entered, derived key's signature would be different and while decrypting the encrypted passwords an exception will be raised which means entered master password is wrong.

Now how is this secure? The derived key will be obtained by using a randomly generated salt which used to derive a fernet key. Fernet key is then converted into urlsafe base64 encoding, as fernet class only accepts urlsafe base64 encoded keys which will be used for encryption/decryption. This fernet key is then used for encryption and decryption of passwords.

NOTE: The fernet key generated will not be same everytime as Initialization Vectors (IV) are used by fernet. Even though fernet key is not same, it will be able to encrypt/decrypt the passwords because we will be storing the randomly generated salts used for encryption of passwords along with their encrypted form of the passwords.

When you run main.py, you will see the following menu:
NOTE: Make sure you have installed all the modules which are used inside main.py and crud.py
1. Login (Existing User)
2. Create An Account (New User)
3. Exit

After logging in, the user can perform the following operations:
1. Add A New Password
2. See All Passwords
3. See Password For A Specific Account
4. Update Password For An Account
5. Delete Password For An Account
6. Change Master Password
7. Delete Your Account & All Saved Passwords
8. Logout

If you decide to change your master password, first a new salt and new encrypted master password is generated for the new entered master password. Then all the passwords stored till now will be decrypted by deriving a key from old master password (as explained above). These decrypted passwords are encrypted by using a new salt, a derived key from the new master password. Now these encrypted passwords will be stored in the database along with their new salts. Finally, the encrypted new master password is also stored along with its new salt in the database.

Tables inside secure-password-manager.db:
1. master_pass
 - schema: master_pass (username text not null, hash text not null, salt text not null)  
2. all_pass
 - schema: all_pass (username text not null, Account_Name text not null, hash text not null, salt text not null)

Users already present in SQLite3 database which can be used for login:
1. Username: Abhishek, Password: Abhishek@123321@
2. Username: temp, Password: temp

Modules you will need to have:
1. sqlite3
2. os
3. hashlib
4. base64
5. cryptography
6. time
7. prettytable

Tech Stack Used: Python.
Database Used: SQLite3.

TLDR: Don't want the hassle of remembering all the passwords of your accounts (or) afraid that your passwords stored in notepad will be stolen/seen by someone? If you said yes to either of the questions then, secure password manager is the solution to your problems. (^_^)

Highlights of Secure Password Manager: 
1. Supports multiple users accounts
2. Remember and login with only one password i.e., master password
3. All stored passwords are encrypted
4. Using master password based key derivation method to encrypt/decrypt stored passwords (including master password)
5. Using randomly generated salts to encrypt and decrypt plaintext/encrypted passwords
6. Each password encrypted (including master password) uses a unique randomly generated salt
7. When master password is changed, all the salts used for encrypting/decrypting the passwords are also changed which adds another layer of security
8. Can increase the number of iterations in key derivation (currently used 10^5 iterations) for more security (but doing so can affect the performance. So, it is important to strike a balance between security and performance according to your needs)
9. Using widely used and secure fernet module in Python for encryption/decryption of passwords