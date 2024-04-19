
passwordfile = "db.txt"

import os
import bcrypt
#part 1, prompt user to choose between login or create account

def main():
	#check that the passwordfile exists
	#if not, create it
	if ( not os.path.exists(passwordfile)):
		open( passwordfile, 'w')
	#run part 1 of the question
	# username, hashed_pass = part1()
	part1()

	#run part 2 of the question
	# part2()
	# part 3, confirm login
	return 0
	
def create_account():
	print("creating an account")
	username = input("username: ")
	hashed_pass = ""
	#check if username already exists
	if ( is_username_exist( username) ):
		#report that username exists, and invalid
		print("username already exists. Please choose a different one.")
		create_account()
	else:
		# proceed with account creation
		password = input( "password: ")
		# hash the password,
		# append the username and hashed_password to the db file
		# salt = bcrypt.gensalt()
		hashed_pass = hash_password( password)
		# hashed_pass = bcrypt.hashpw( password, salt)
		append_dbfile = open( passwordfile, 'a')
		# store_string = username + "  " + str( hashed_pass ) + " " + str(salt)
		store_string = username + " " + str( hashed_pass ) # remove salt
		# append_dbfile.write( username, hashed_pass)
		append_dbfile.write( store_string + '\n')
		# append_dbfile.write("\n") # set to new line
		append_dbfile.close()
	return username, hashed_pass
	
def loginto_account():
	# part 3
#  If the user has a registered account in db.txt and enters a valid password 
#  (that is properly matched against the salted hash), 
#  they can attempt to login into their account by choosing option (2) at the initial prompt
	print("username and password: ")
	username = input("username: ")
	#check if username already exists
	if ( is_username_exist( username) ):
		# get the user entry
		user_entry = get_user_entry( username) # an array
		print("entry user: ", user_entry)
		# stored_hash = user_entry[1]
		# stored_salt = user_entry[2]
		stored_hash = user_entry[1]
		print("User stored: ", user_entry[0])
		print("hash stored: ", stored_hash)
		# retrieve salt for user
		# salt = 
		#proceed for login
		password = input("password: ")
		# compare hashed passwords
		# '''
		# hashed_pass = hash_password(password, stored_salt)
		# check_str = username + "  "+ str(hashed_pass)
		# print("hashed password: " , hashed_pass)
		# open_file = open(passwordfile, 'r')
		# if ( check_str in open_file.read() ): 
		# 	# the username and password_hash match in the file
		# 	open_file.close()
		# 	return True
		# else:
		# 	# fail login
		# 	open_file.close()
		# 	return False
		# '''
		#encode password to bytes for hash check
		# password_bytes = password.encode ("utf-8")
		password_bytes = bytes( password, 'utf-8')
		# verify passwords post-hash
		if ( bcrypt.checkpw( password_bytes, stored_hash) ):
			# login successful
			return True
		else:
			return False
	else:
		#report that username is not exist
		print("no username by that. Please try again.")
		loginto_account()
	
	return 0
	
def verify_user ( username = ""):
	# given the username, verify identity with password and hash
	pass 

def is_username_exist( username = ""):
# return true if the given username already exists in the user info file
	is_exist = False
	read_file = open(passwordfile, 'r')
	is_exist = ( username in read_file.read())
	read_file.close()
	return is_exist

def get_user_entry( username = ""):
	# return the array of login info for the user
	open_file = open( passwordfile, 'r')
	file_contents = open_file.readlines()
	# file_contents = open_file.read()
	search_str = username + " " #include the separating space of the username
	line_number = 0
	for entry in file_contents: #cycle through the lines of the db file
		if search_str in entry: # looking for the username to match
			break 
		line_number += 1
	# line_number = file_contents.index(search_str) # find the line number by the username spacer, the index
	print("line index: " , line_number)
	chosen_str = file_contents[line_number] # get the line contents of the username match
	print("entry number: ", line_number)
	print("entry string: ", chosen_str)
	line_array = chosen_str.split(" ") # [1] username, [2] hashed_password
	return line_array

	
def hash_password ( plain_password = ""):
	# return the salted hashed version of the password string
	# hashed_string = ""
	# bytes = plain_password.encode('utf-8')
	bytes_pass = bytes( plain_password, 'utf-8')
	# bytes = str.encode( plain_password)
	salt = bcrypt.gensalt()
	
	# hashed_string = str( bcrypt.hashpw( bytes, salt) )
	# hashed_string = bcrypt.hashpw( bytes, salt_int)
	# salt = salt_int 
	print("salt: ", salt)
	hashed_string = bcrypt.hashpw( bytes_pass, salt)
	return hashed_string

def match_username_password ( username = "", hashed_pass = ""):
	# in the password file, compare the username to the password on the same line
	# is_matched = False
	open_file = open( passwordfile, 'r')
	user_pass_str = username + " " + hashed_pass
	is_matched = ( user_pass_str in open_file.read() )
		# if the username and hahs are in the file, return trueu
	open_file.close()
	return is_matched

def part1():
	print("""Would you like to:
	(1): create an account
	(2): login into an existing account""")
	user_input = input()
	
	username = ""
	hashed_pass = ""
	if user_input == "1":
		create_account()
	elif user_input == "2":
		#part3
		login_state = loginto_account()
		if login_state: # login successful
			print("login successful")
		else: #login failed
			print("login failed")
# part1()

main()