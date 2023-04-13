def emailVal(email):
    utMail = "@spartans.ut.edu"
    if email[-16:] == utMail:
        return True
    else:
        return False


email = "alex.rodriguez@spartans.ut.edu"
print(emailVal(email))