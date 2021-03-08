import hashlib

def crack_sha1_hash(hash, use_salts = False):
  with open('top-10000-passwords.txt', 'r') as passwords_file:
    for password in passwords_file:
      password = str(password.splitlines()[0])
      if not use_salts:
        hashed_password = hashlib.sha1(password.encode()).hexdigest()
        if hash == hashed_password:
          return(password)

      with open('known-salts.txt', 'r') as salts_file:
        for salt in salts_file:
          salt = str(salt.splitlines()[0])
          
          password_with_salt = salt + password + salt
          password_prepend_salt = salt + password
          password_append_salt = password + salt
          
          hashed_password = hashlib.sha1(password_with_salt.encode()).hexdigest()
          hashed_password2 = hashlib.sha1(password_prepend_salt.encode()).hexdigest()
          hashed_password3 = hashlib.sha1(password_append_salt.encode()).hexdigest()

          if hash == hashed_password2 or hash == hashed_password or hash == hashed_password3:
            return(password)
  
  return('PASSWORD NOT IN DATABASE')