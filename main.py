import sqlite3, crud
import os, hashlib, base64, time
from cryptography.fernet import Fernet
import cryptography.fernet
from prettytable import PrettyTable

connection = sqlite3.connect('secure-password-manager.db')
cursor = connection.cursor()

# SQLite3 functions creation if needed

class Auth():
    def does_user_already_exists(self, entered_username):
        # USED TO CHECK IF A USER ALREADY EXISTS WITH THAT USERNAME
        query = 'select username from master_pass where username = ?;'
        cursor.execute(query, (entered_username,))
        result = cursor.fetchall()
        return False if len(result) == 0 else True
    
    def authenticate_user(self, entered_username, entered_password):
        # return True/False
        # if False, no such username in DB
        if not self.does_user_already_exists(entered_username): return False
        else:
            # authenticate password
            answer = False
            query = 'select hash, salt from master_pass where username = ?;'
            result = cursor.execute(query, (entered_username,)).fetchall()
            # print(result) # [('gAAAAABk2MRs530Svl4-XPD541GApiz56bkzd94fhiUIflJp_qki-2hVz9PrnFq-3-mNI4pMP7cpUtbJS-X3ombEQTcmQBV1QA==',)]
            master_password_hash_in_db, salt_of_master_password_in_db = result[0][0], result[0][1]

            entered_derived_key = hashlib.pbkdf2_hmac('sha256', entered_password.encode('utf-8'), salt_of_master_password_in_db, 100000, dklen=32)

            fernet_key = base64.urlsafe_b64encode(entered_derived_key)
            fernet = Fernet(fernet_key)

            try:
                temp = fernet.decrypt(master_password_hash_in_db.encode()).decode()
                if temp == entered_password: 
                    answer = True
            except cryptography.fernet.InvalidToken:
                """
                Otherwise, an exception is raised (specifically, cryptography.fernet.InvalidToken), indicating that the decryption failed,
                which happens if the entered password doesn't match the original password.
                """
                pass
            return answer


class Session(Auth):
    entered_username, entered_pass = "", ""
    wrong_password_attempts = 0
    login_success, show_menu_choice, user_menu_choice = False, 3, 6

    def show_menu(self):
        print("""
Welcome To Secure Password Manager! \(^_^)/\n
Sign In/Sign Up Menu
1. Login (Existing User)
2. Create An Account (New User)
3. Exit
""")
        self.show_menu_choice = int(input('Enter your choice: '))

    def user_menu(self):
        print("""
What Do You Want To Do, {}?
1. Add A New Password
2. See All Passwords
3. See Password For A Specific Account
4. Update Password For An Account
5. Delete Password For An Account
6. Change Master Password
7. Delete Your Account & All Saved Passwords
8. Logout
        """.format(self.entered_username))
        self.user_menu_choice = int(input("{}, Now Enter A Number To Perform An Operation: ".format(self.entered_username)))

    def sign_up(self):
        while True:
            self.entered_username = input('Enter Your Username: ')
            self.entered_pass = input('Enter Your Password: ')
            if self.does_user_already_exists(self.entered_username):
                print("\nALREADY A USER EXISTS IN DATABASE!\n\nEnter New Username And Password To Sign Up!")
                break
            else: 
                # create new account
                result_list = crud.hash_and_salt_used(self.entered_username, self.entered_pass)
                query = 'insert into master_pass values (?, ?, ?);'
                cursor.execute(query, (self.entered_username, result_list[0], result_list[1]))
                print("\nACCOUNT CREATED SUCCESSFULLY! (^_^)")
                break
    
    def login(self):
        while not self.login_success and self.show_menu_choice == 1:
            self.entered_username = input("\nEnter Your Username: ")
            self.entered_pass = input("Enter Your Master Password: ")

            if activity.authenticate_user(self.entered_username, self.entered_pass):
                print("\nACCESS GRANTED!\n\nWelcome back, {}. (^ v ^)".format(self.entered_username))
                self.login_success = True
            else:
                self.wrong_password_attempts += 1
                print("\nINVALID USERNAME/PASSWORD ENTERED! PLEASE TRY AGAIN! (O_O)")

                if self.wrong_password_attempts == 3:
                    print("\nTHREE CONSECUTIVE WRONG LOGIN ATTEMPTS WERE MADE! (O_o)\nTry Again After 9 Seconds...")
                    time.sleep(9)
                    self.wrong_password_attempts = 0
                    self.show_menu_choice = 3

# START
activity = Session()

while True:
    activity.show_menu()
    if activity.show_menu_choice == 3: break
    elif activity.show_menu_choice == 2: 
        # new account
        activity.sign_up()
        continue
    elif activity.show_menu_choice == 1: 
        activity.login()
        if activity.show_menu_choice == 3: activity.show_menu_choice = 1

        if activity.login_success: break
    else: print("\nENTER A VALID NUMBER TO PERFORM AN OPERATION!")

# show operations for successfully logged in user
while activity.login_success and activity.show_menu_choice == 1:
    activity.user_menu()
    if activity.user_menu_choice == 1:
        # add an account & its password
        account_name = input("Enter Account Name To Store: ")
        temp = crud.add_a_new_password(activity.entered_pass)
        query = "insert into all_pass values (?, ?, ?, ?);"
        cursor.execute(query, (activity.entered_username, account_name, temp[0], temp[1]))
        print("\nSUCCESSFULLY STORED PASSWORD FOR {}!".format(account_name))

    elif activity.user_menu_choice == 2:
        # view all passwords of accounts related to that user
        query = "select * from all_pass where username = ? order by account_name;"
        result = cursor.execute(query, (activity.entered_username,)).fetchall()

        t = PrettyTable()
        t.field_names = ['S. No.', 'User', 'Account Name', 'Password']
        for ind, (row) in enumerate(result, start=1):
            value = crud.hashed_password_to_plaintext(row[2], row[3], activity.entered_pass)
            t.add_row([ind, row[0], row[1], value])
        print(t)

    elif activity.user_menu_choice == 3:
        # search for a specific account
        entered_account_name = input("Enter The Account Name You Want To See Password For: ").lower()
        query = "select * from all_pass where username = ? and lower(Account_Name) = ?;"
        result = cursor.execute(query, (activity.entered_username, entered_account_name)).fetchall()
        
        if len(result) != 0:
            t = PrettyTable()
            t.field_names = ['S. No.', 'User', 'Account Name', 'Password']
            for ind, (username, account_name, hash, salt) in enumerate(result, start=1):
                value = crud.hashed_password_to_plaintext(hash, salt, activity.entered_pass)
                t.add_row([ind, username, account_name, value])
            print(t)
        else:
            print("\nNO ACCOUNT WITH THE NAME {} EXISTS!\n".format(entered_account_name))

    elif activity.user_menu_choice == 4:
        # update a stored password
        entered_account_name = input("Enter The Account Name You Want To Update The Password: ")

        temp_list = crud.update_a_password(entered_account_name, activity.entered_pass)
        # need to update hash and salt both in DB. hash, salt => temp_list[0], temp_list[1]
        query = "update all_pass set hash = ?, salt = ? where username = ? and account_name = ?;"
        cursor.execute(query, (temp_list[0], temp_list[1], activity.entered_username, entered_account_name))
        
        print("\nPASSWORD OF {} UPDATED SUCCESSFULLY!".format(entered_account_name))
    elif activity.user_menu_choice == 5:
        # Delete an account password
        print("\nCAUTION: THE DELETION CHANGES CAN'T BE UNDONE. (O_O)\nAre You Sure You Want To Delete A Stored Password? (y/n)")
        char_entered = input()
        if char_entered == 'y':
            entered_account_name = input("Enter The Account Name You Want To Delete Permanently: ")
            query = "delete from all_pass where username = ? and account_name = ?;"
            cursor.execute(query, (activity.entered_username, entered_account_name))
            print("\nSUCCESSFULLY DELETED DATA RELATED TO {}".format(entered_account_name))
        else: continue

    elif activity.user_menu_choice == 6:
        # master password reset
        """
        Need to keep new_derived_key, new_hash, new_salt outside the loop. 
        With old hash in DB need to decrypt all stored passwords of a user, then encrypt with new_derived_key.
        Use functions for computing new hash, salt, derived_key.
        Lastly update hash in master_pass table in DB for that user. 
        
        do i need to update activity.entered_pass in the end? YES
        """
        print("\nCAUTION: YOU ARE ABOUT TO CHANGE YOUR MASTER PASSWORD. (O_O)\nAre You Sure You Want To Change Your Master Password? (y/n)")
        char_entered = input()
        if char_entered == 'y':
            new_entered_master_pass = input("Enter Your New Master Password: ")
            new_master_hash, new_master_salt = "", ""
            temp_list = crud.encrypt_the_new_master_password(new_entered_master_pass)
            new_master_hash, new_master_salt = temp_list[0], temp_list[1]
            # print("temp_list[0]:", temp_list[0])
            # print("temp_list[1]:", temp_list[1])

            # query for user related paswords
            query = "select * from all_pass where username = ?;"
            result = cursor.execute(query, (activity.entered_username,)).fetchall()
            for ind, (username, account_name, hash, salt) in enumerate(result, start=1):
                stored_pass_plaintext = crud.hashed_password_to_plaintext(hash, salt, activity.entered_pass)
                temp_list = crud.encrypt_stored_password_with_new_master_password(stored_pass_plaintext, new_entered_master_pass)
                # list 0, 1 are new_cipher, new_salt respectively
                query = "update all_pass set hash = ?, salt = ? where account_name = ?;"
                cursor.execute(query, (temp_list[0], temp_list[1], account_name))

            # update master_pass with new set of hash, salt
            cursor.execute("update master_pass set hash = ?, salt = ? where username = ?", (new_master_hash, new_master_salt, activity.entered_username))
            activity.entered_pass = new_entered_master_pass
            print("\nSUCCESSFULLY CHANGED MASTER PASSWORD!")

        else: continue


    elif activity.user_menu_choice == 7:
        # delete account
        print("\nCAUTION: YOU ARE ABOUT TO PERMANENTLY DELETE YOUR ACCOUNT AND ALL THE PASSWORDS YOU HAVE STORED TILL NOW. (O_O)")
        print("\nAre You Sure You Want To Delete Your Account, {}? (y/n)".format(activity.entered_username))
        char_entered = input()
        if char_entered == 'y':
            query = "delete from master_pass where username = ?;"
            cursor.execute(query, (activity.entered_username,))
            query = "delete from all_pass where username = ?;"
            cursor.execute(query, (activity.entered_username,))
            print("\nSUCCESSFULLY DELETED YOUR ACCOUNT, {}!".format(activity.entered_username))
            break
        else: continue

    elif activity.user_menu_choice == 8: 
        # Logout
        activity.login_success = False
        break
    else: print("\nENTER A VALID NUMBER TO PERFORM AN OPERATION! (O_O)\n")

if not activity.wrong_password_attempts == 3:
    print("\nBye, {}. (^_^)".format(activity.entered_username))
print("\nSession Ended!")


connection.commit()
connection.close()

"""
create table master_pass (username text not null, hash text not null, salt text not null);

create table all_pass (username text not null, Account_Name text not null, hash text not null, salt text not null);
"""