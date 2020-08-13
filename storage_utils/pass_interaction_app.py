import json
import os
import random
import string
from typing import Optional, Dict, Tuple, Callable, List

from storage_utils.AES import AES
from storage_utils.ct import PASS_STORAGE_ENV_KEY_PATH, SHOW_RECORDS_OPTION, LIST_ALL_SERVICES, ADD_RECORD,\
    DEL_RECORD, EDIT_RECORD, SHOW_HELP, QUIT, GEN_KEY, PATH_TO_PASSWORDS, USERNAME_KEY, PASSWORD_KEY,\
    STOP, PATH_TO_KEY

from storage_utils.utils import is_file, is_key_path_correct, get_str_from_num, get_text_from_list_of_nums


class PassStorage:
    __slots__ = ["key_path", "all_passwords", "aes", "commands"]

    def __init__(self):
        self.aes: Optional[AES] = None
        self.commands: Optional[Dict[str, Tuple[str, Callable]]] = None
        self.all_passwords: Optional[Dict[str, List[Dict[str, str]]]] = None
        self.key_path: Optional[str] = None

    #########################
    # commands
    #########################

    def show_records(self):
        service = self._input_service()
        while service != STOP:
            for num, acc in enumerate(self.all_passwords[service]):
                print(f"{num}. username = {acc[USERNAME_KEY]}   |   password={acc[PASSWORD_KEY]}")
            acc_num = input(f"input num of acc to show full info(or '{STOP}' to stop) \n>> ")
            while acc_num != STOP:
                acc_num, check_res = self._check_acc_num(acc_num, service)
                if check_res is True:
                    self._print_account(service, acc_num)
                acc_num = input(f"input num of acc to show full info(or '{STOP}' to stop) \n>> ")
            print(f"input '{STOP}' to stop")
            service = self._input_service()

        print("finish show_records")

    def list_all(self):
        for num, service in enumerate(sorted(self.all_passwords.keys())):
            print(f"{num}. {service}")
        print("finish list_all")

    def add(self):
        cur_service = input("input service >> ")
        self.all_passwords.setdefault(cur_service, [])
        self._add_account(cur_service)
        print("finish adding")

    def delete(self):
        service = self._input_service()
        while service != STOP:
            ans = input("delete the whole service? [y/n]")
            if ans == "y":
                del self.all_passwords[service]
            else:
                self._delete_accounts(service)

            print(f"input '{STOP}' to stop")
            service = self._input_service()
        print("finish deleting")

    def edit(self):
        service = self._input_service()
        self._print_all_accounts(service)
        num_to_edit = input(f"input account number to edit ['{STOP}' to stop] >> ")
        while num_to_edit != STOP:
            num_to_edit, good_res = self._check_acc_num(num_to_edit, service)
            if good_res:
                self._edit_acc(service, num_to_edit)
            num_to_edit = input(f"input account number to edit ['{STOP}' to stop] >> ")
            print("finish editing")

    def help(self):
        for k, v in self.commands.items():
            print(f" {k} - {v[0]}")

    def quit(self):
        saves = input("Save? y/[something else]")
        if saves == 'y':
            print("Saving...")
            try:
                self._save()
                print(f"Passwords are saved into {PATH_TO_PASSWORDS}")
            except Exception as e:
                print(f"while saving error happened: {e}")

    @staticmethod
    def gen_aes_key(key_len=128):
        text_key = [random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits)
                    for _ in range(key_len // 8)]
        symb_codes = [str(ord(symb)) for symb in text_key]
        symb_codes = ["0" * (3 - len(code)) + code for code in symb_codes]
        symb_codes = ''.join(symb_codes)

        with open(PATH_TO_KEY, 'w') as file:
            file.write(symb_codes)
        print(f"Key is written into '{PATH_TO_KEY}'")
        print(f"You can move your key into any directory and create an environment variable "
              f"'{PASS_STORAGE_ENV_KEY_PATH}' with the path to the new location.")

    #########################
    # install pass storage
    #########################

    def install(self):
        self.gen_aes_key()

    #########################
    # run pass storage
    #########################

    def run(self):
        self._init_after_install()
        print("input 'h' to print all commands")
        while True:
            input_command = input(">> ")
            if input_command in self.commands.keys():
                self.commands[input_command][1]()
                if input_command == QUIT:
                    break
            else:
                print("wrong command")
        print("finishing pass storage")

    #########################
    # utils
    #########################

    def _init_key_path(self):
        try:
            key_path = os.environ[PASS_STORAGE_ENV_KEY_PATH]
        except Exception:
            key_path = input(f"input path to file with key "
                             f"(or close the application and create an environment variable "
                             f"'{PASS_STORAGE_ENV_KEY_PATH}' with the path to the location of the file with the key) >> ")

        if is_key_path_correct(key_path):
            self.key_path = key_path
        else:
            raise ValueError(f"wrong key path = {key_path}")

    def _get_key(self) -> str:
        with open(self.key_path, "r") as file:
            text_key = file.read()
        return text_key

    @staticmethod
    def _get_list_of_nums(nums_in_row: str) -> List[int]:
        characters_per_num = int(nums_in_row[0], 10)
        list_of_nums = [int(nums_in_row[((i - 1) * characters_per_num + 1):(i * characters_per_num + 1)], 10)
                        for i in range(1, 1 + (len(nums_in_row) - 1) // characters_per_num)]
        return list_of_nums

    def _decrypt_all(self) -> Dict:
        if not is_file(PATH_TO_PASSWORDS):
            print(f"file {PATH_TO_PASSWORDS} does't exist")
            return {}

        with open(PATH_TO_PASSWORDS, "r") as file:
            encrypted_passwords = file.read()
        if encrypted_passwords == "":
            print("file with passwords is empty")
            return {}

        encrypted_codes = self._get_list_of_nums(encrypted_passwords)
        self.aes.open_bytes = encrypted_codes[:]
        self.aes.cipher_bytes = encrypted_codes[:]
        open_codes = self.aes.decrypt()
        open_pass = get_text_from_list_of_nums(open_codes)
        try:
            dict_open_passwords = json.loads(open_pass)
        except json.decoder.JSONDecodeError as e:
            print(f"error happened while opening passwords the file")
            raise e
        return dict_open_passwords

    def _init_after_install(self):
        self._init_key_path()
        self.aes = AES()
        self.aes.key = self._get_key()
        self.commands = {
            SHOW_RECORDS_OPTION: ("show service records", self.show_records),
            LIST_ALL_SERVICES: ("list all services", self.list_all),
            ADD_RECORD: ("add a record", self.add),
            DEL_RECORD: ("delete a record", self.delete),
            EDIT_RECORD: ("edit a record", self.edit),
            SHOW_HELP: ("show help", self.help),
            QUIT: ("quit", self.quit),
            GEN_KEY: (f"gen key (will be written into '{PATH_TO_KEY}')", self.gen_aes_key)
        }
        self.all_passwords = self._decrypt_all()

    def _input_service(self):
        while True:
            service = input("input service >> ")
            if service in self.all_passwords.keys():
                break
            print("wrong service name")
            self.list_all()
        return service

    def _print_all_accounts(self, service):
        for num in range(len(self.all_passwords[service])):
            print(f"{num}.")
            self._print_account(service, num)
            print("\n")

    def _check_acc_num(self, acc_num: str, service: str) -> Tuple[Optional[int], bool]:
        try:
            acc_num = int(acc_num, 10)
            if len(self.all_passwords[service]) < acc_num and acc_num >= 0:
                return acc_num, True
            else:
                print(f"num not in ranges [0 <= num < {len(self.all_passwords[service])}]")
        except Exception:
            print("wrong num format (not int)")
        return None, False

    def _print_account(self, service: str, acc_num: int):
        for k, v in self.all_passwords[service][acc_num].items():
            print(f"{k} = {v}")

    def _add_account(self, service):
        username = input("input username >> ")
        password = input("input password >> ")
        new_account = {
            USERNAME_KEY: username,
            PASSWORD_KEY: password
        }
        add_field = input("add a field[y/n] >> ")
        while add_field == "y":
            field = input("input a field name >> ")
            f_value = input("input a field value >> ")
            new_account[field] = f_value
            add_field = input("add a field[y/n] >> ")

        self.all_passwords[service].append(new_account)

    def _delete_fields(self, service: str, acc_num: int):
        self._print_account(service, acc_num)
        field_name = input(f"input field name to delete ['{STOP}' to stop] >> ")
        while field_name != STOP:
            if field_name in {USERNAME_KEY, PASSWORD_KEY}:
                print("deleting username or password is prohibited")
            elif field_name in self.all_passwords[service][acc_num]:
                del self.all_passwords[service][acc_num][field_name]
            else:
                print(f"field name {field_name} not found.")
            field_name = input(f"input field name to delete ['{STOP}' to stop] >> ")



    def _delete_accounts(self, service: str):
        self._print_all_accounts(service)
        acc_num = input(f"input account number ['{STOP}' to stop] >> ")
        while acc_num != STOP:
            ans = input("delete the whole account? [y/n]")
            if ans == "y":
                acc_num, check_res = self._check_acc_num(acc_num, service)
                if check_res is True:
                    del self.all_passwords[service][acc_num]
            else:
                self._delete_fields(service, acc_num)

            acc_num = input(f"input account number ['{STOP}' to stop] >> ")

    def _edit_acc(self, service, num_of_acc):
        for key in self.all_passwords[service][num_of_acc].keys():
            print(key)

        while True:
            field = input(f"input field to edit ['{STOP}' to stop] >> ")
            if field == STOP:
                break
            if field not in self.all_passwords[service][num_of_acc].keys():
                print("There is no such field")
                continue

            f_value = input("input new field value >> ")
            self.all_passwords[service][num_of_acc][field] = f_value

    def _save(self):
        pack_passwords = json.dumps(self.all_passwords)
        self.aes.prepare_text(pack_passwords)
        encr_passwords = self.aes.encrypt()

        encr_text = self._get_encr_text(encr_passwords)

        with open(PATH_TO_PASSWORDS, "w") as file:
            file.write(encr_text)

    def _get_encr_text(self, encr_pass):
        encr_pass = [str(i) for i in encr_pass]
        max_len = len(max(encr_pass, key=len))
        if len(str(max_len)) > 1:
            print("error. too long numbers. mass will be stored in the file")
            return str(encr_pass)
        encr_text = str(max_len)
        for num in encr_pass:
            encr_text += get_str_from_num(max_len, num)
        return encr_text



if __name__ == "__main__":
    p = PassStorage()
    p.run()
