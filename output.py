# this is only for seeing output
import sqlite3

con = sqlite3.connect('secure-password-manager.db')
cursor = con.cursor()

print("Users in database:")
result = cursor.execute("select * from master_pass;")
for i in result: print(i[0])

print("\nUsers and their accounts:")
result = cursor.execute("select * from all_pass;")
for i in result: print(i[0], i[1])

# con.commit()
con.close()