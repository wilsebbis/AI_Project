import bcrypt

master_password = "your_master_password"  # Replace with your actual master password
hashed_password = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())
print(hashed_password.decode())