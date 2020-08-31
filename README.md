# password_storage

Simple application for password storage in **remote **.

## SetUp
1. install libs from data/requirements.txt
2. run install_pass_storage.py

Creates key in *data/key.txt*. You can move your key into any directory and create an environment variable
***PASS_STORAGE_KEY_PATH*** with the path to the new location. 
When you run app you will input path to key.txt or it will be taken from the ***PASS_STORAGE_KEY_PATH*** location. 

## Run
run run_pass_storage.py

### Commands:
 - sh - show service records
 - ls - list all services
 - a - add a record
 - d - delete a record
 - e - edit a record
 - h - show help
 - q - quit
 - ck - change key
 - bu - create backup into json


## Run with arguments
run run_pass_storage.py with some of the arguments below

### Arguments:

* -h, --help - show this help message and exit<br>
* -s S       - service name<br>
* -acc ACC   - account login<br>
* -p P       - print mode
  - default - copy to clipboard</pre>
  - short - only service, login and password<br>
  - full - all account info<br>
