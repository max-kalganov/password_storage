import os
import json
import random
import string
import pyperclip

from typing import Optional, Dict, Tuple, Callable, List, Union

from storage_utils.AES import AES
from storage_utils.ct import PASS_STORAGE_ENV_KEY_PATH, SHOW_RECORDS_OPTION, LIST_ALL_SERVICES, ADD_RECORD, \
    DEL_RECORD, EDIT_RECORD, SHOW_HELP, QUIT, CHANGE_KEY, PATH_TO_PASSWORDS, LOGIN, PASSWORD, \
    STOP, PATH_TO_KEY, BACKUP

from storage_utils.utils import is_file, is_key_path_correct, format_str_num, get_text_from_list_of_nums


class PassStorage:
    __slots__ = ["key_path", "all_passwords", "aes", "commands", "new_key"]

    def __init__(self):
        self.aes: Optional[AES] = None
        self.commands: Optional[Dict[str, Tuple[str, Callable]]] = None
        self.all_passwords: Optional[Dict[str, List[Dict[str, str]]]] = None
        self.key_path: Optional[str] = None
        self.new_key: Optional[str] = None

    #########################
    # commands
    #########################

    def show_services(self):
        self._process_services(self._show_accounts)
        print("finish show_records")

    def list_all(self):
        for num, service in enumerate(sorted(self.all_passwords.keys())):
            print(f"{num}. {service}")
        print("finish list_all")

    def add(self):
        cur_service = input("input service name >> ")
        self.all_passwords.setdefault(cur_service, [])

        self._add_account(cur_service)
        print("finish adding")

    def delete(self):
        self._process_services(self._delete_service)
        print("finish deleting")

    # TODO: ? unify edit and add
    def edit(self):
        self._edit_service_name()
        self._process_services(self._edit_accounts)
        print("finish editing")

    def help(self):
        for k, v in self.commands.items():
            print(f" {k} - {v[0]}")

    def quit(self):
        saves = input("Save? y/[something else]")
        if saves == 'y':
            print("Saving...")
            if self.new_key is not None:
                self.aes.key = self.new_key
            try:
                self._save()
                print(f"Passwords are saved into {PATH_TO_PASSWORDS}")

                if self.new_key is not None:
                    try:
                        self._save_key(new_key=self.new_key, key_path=self.key_path)
                    except Exception as e:
                        print(f"while saving key error happened: {e}")
                        self._save_key(new_key=self.new_key, key_path=PATH_TO_KEY)

            except Exception as e:
                print(f"while saving error happened: {e}")

    #########################
    #      create backup
    #########################

    def backup(self):
        with open('data/backup.json', 'w') as fp:
            json.dump(self.all_passwords, fp)
        print('backup save in data/backup.json')

    #########################
    # install pass storage
    #########################

    def install(self):
        self._gen_aes_key()

    #########################
    # run pass storage
    #########################
    def run_with_params(self, s, acc, p):
        output = []
        self._init_after_install()
        for service, acc_list in self.all_passwords.items():
            for account_info in acc_list:
                if (service == s or s is None) and (account_info[LOGIN] == acc or acc is None):
                    if p == 'short':
                        output.append({'service': service,
                                       LOGIN: account_info[LOGIN],
                                       PASSWORD: account_info[PASSWORD]})
                    else:
                        output.append({'service': service,
                                       **account_info})

        if p is None:
            if len(output) == 1:
                pyperclip.copy(output[0][PASSWORD])
            else:
                print('found many accounts')
        else:
            print(output)

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

    @staticmethod
    def _save_key(new_key, key_path):
        with open(key_path, 'w') as file:
            file.write(new_key)

        print(f"Key is written into '{key_path}'")
        if key_path == PATH_TO_KEY:
            print(f"You can move your key into any directory and create an environment variable "
                  f"'{PASS_STORAGE_ENV_KEY_PATH}' with the path to the new location.")

    def _gen_aes_key(self, key_len=128, key_path: str = PATH_TO_KEY, save_in_file: bool = True):
        text_key = [random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits)
                    for _ in range(key_len // 8)]
        symb_codes = [str(ord(symb)) for symb in text_key]
        symb_codes = ["0" * (3 - len(code)) + code for code in symb_codes]
        symb_codes = ''.join(symb_codes)

        if save_in_file:
            self._save_key(new_key=symb_codes, key_path=key_path)
        return symb_codes

    def _init_key_path(self):
        try:
            key_path = os.environ[PASS_STORAGE_ENV_KEY_PATH]
        except Exception:
            key_path = input(f"input path to file with key\n "
                             f"(or close the application and create "
                             f"an environment variable '{PASS_STORAGE_ENV_KEY_PATH}'. \n"
                             f"It should contain the path to the location of the file with the key) >> ")

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
            SHOW_RECORDS_OPTION: ("show service records", self.show_services),
            LIST_ALL_SERVICES: ("list all services", self.list_all),
            ADD_RECORD: ("add a record", self.add),
            DEL_RECORD: ("delete a record", self.delete),
            EDIT_RECORD: ("edit a record", self.edit),
            SHOW_HELP: ("show help", self.help),
            QUIT: ("quit", self.quit),
            CHANGE_KEY: (f"change key", self._change_key),
            BACKUP: (f"create backup into json", self.backup)
        }
        self.all_passwords = self._decrypt_all()

    @staticmethod
    def _input_new_field(fields, msg: str) -> Union[str, STOP]:
        field = input(msg + f" >> ")
        while field in fields:
            field = input(f"{msg} (or '{STOP}' to stop) >> ")
            if field not in fields or field == STOP:
                break
            print(f"{field} is already in {fields}")
        return field

    def _input_service(self):
        while True:
            service = input(f"input service (or '{STOP}' to stop)>> ")
            if service in self.all_passwords.keys() or service == STOP:
                break
            print("wrong service name")
            self.list_all()
        return service

    def _change_key(self):
        self.new_key = self._gen_aes_key(key_path=self.key_path, save_in_file=False)

    def _print_all_accounts(self, service):
        for num in range(len(self.all_passwords[service])):
            print(f"{num}. {self._account_info(service, num)}")

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

    def _account_info(self, service: str, acc_num: int) -> str:
        return f"{LOGIN} = {self.all_passwords[service][acc_num][LOGIN]}   |   " \
               f"{PASSWORD} = {self.all_passwords[service][acc_num][PASSWORD]}"

    def _print_account_full(self, service: str, acc_num: int):
        for k, v in self.all_passwords[service][acc_num].items():
            print(f"{k} = {v}")

    def _show_accounts(self, service: str):
        self._process_accounts(service, action_descr="to show full info", command=self._print_account_full)

    def _get_all_logins_to_acc_num(self, service) -> Dict[str, int]:
        return {acc[LOGIN]: i for i, acc in enumerate(self.all_passwords[service])}

    def _add_account(self, service: str):
        all_logins = self._get_all_logins_to_acc_num(service)
        add_field = "y"
        login = input("input login >> ")
        if login not in all_logins:
            password = input("input password >> ")
            cur_account = {
                LOGIN: login,
                PASSWORD: password
            }
            self.all_passwords[service].append(cur_account)
            add_field = input("add a field[y/n] >> ")
        else:
            cur_account = self.all_passwords[service][all_logins[login]]
            self._print_account_full(service, all_logins[login])

        while add_field == "y":
            field = self._input_new_field(cur_account.keys(), "input a field name")
            f_value = input("input a field value >> ")
            cur_account[field] = f_value
            add_field = input("add a field[y/n] >> ")

    def _delete_service(self, service):
        ans = input("delete the whole service? [y/n]")
        if ans == "y":
            del self.all_passwords[service]
        else:
            self._delete_accounts(service)

    def _delete_fields(self, service: str, acc_num: int):
        def delete_field(cur_service, cur_acc_num, field_name):
            if field_name in {LOGIN, PASSWORD}:
                print("deleting login or password is prohibited")
            else:
                del self.all_passwords[service][acc_num][field_name]

        self._process_fields(service, acc_num, action_descr="to delete", command=delete_field)

    def _delete_accounts(self, service: str):
        def delete_acc(cur_service, acc_num):
            ans = input("delete the whole account? [y/n]")
            if ans == "y":
                del self.all_passwords[cur_service][acc_num]
            else:
                self._delete_fields(cur_service, acc_num)

        self._process_accounts(service, action_descr="", command=delete_acc)

    def _edit_service_name(self):
        edit_service_name = input("edit service name? (y/n) >> ")
        while edit_service_name == "y":
            old_service_name = self._input_service()
            new_service_name = self._input_new_field(self.all_passwords.keys(), "input new service name")
            self.all_passwords[new_service_name] = self.all_passwords[old_service_name]
            del self.all_passwords[old_service_name]
            edit_service_name = input("edit service name? (y/n) >> ")

    def _edit_fields(self, service, acc_num):
        all_logins = self._get_all_logins_to_acc_num(service)

        def edit_field(cur_service, cur_acc_num, field_name):
            if field_name == LOGIN:
                f_value = self._input_new_field(all_logins.keys(), "input new field value")
                all_logins[f_value] = all_logins[field_name]
                del all_logins[field_name]
            else:
                f_value = input("input new field value >> ")

            self.all_passwords[cur_service][cur_acc_num][field_name] = f_value

        self._process_fields(service, acc_num, "to edit", command=edit_field)

    def _edit_accounts(self, service: str):
        self._process_accounts(service, action_descr="to edit", command=self._edit_fields)

    def _save(self):
        pack_passwords = json.dumps(self.all_passwords)
        self.aes.prepare_text(pack_passwords)
        encr_passwords = self.aes.encrypt()
        encr_text = self._get_encr_text(encr_passwords)

        with open(PATH_TO_PASSWORDS, "w") as file:
            file.write(encr_text)

    @staticmethod
    def _get_encr_text(encr_pass):
        encr_pass = [str(i) for i in encr_pass]
        max_len = len(max(encr_pass, key=len))
        if len(str(max_len)) > 1:
            print("error. too long numbers. mass will be stored in the file")
            return str(encr_pass)
        encr_text = str(max_len)
        for str_num in encr_pass:
            encr_text += format_str_num(max_len, str_num)
        return encr_text

    def _process_services(self, command: Callable):
        service = self._input_service()
        while service != STOP:
            command(service)

            self.list_all()
            service = self._input_service()

    def _process_accounts(self, service: str, action_descr: str, command: Callable):
        full_action_descr = ' ' + action_descr if action_descr else ''
        self._print_all_accounts(service)
        acc_num = input(f"input account number{full_action_descr} ['{STOP}' to stop] >> ")
        while acc_num != STOP:
            acc_num, check_res = self._check_acc_num(acc_num, service)
            if check_res is True:
                command(service, acc_num)

            self._print_all_accounts(service)
            acc_num = input(f"input account number {full_action_descr} ['{STOP}' to stop] >> ")

    def _process_fields(self, service: str, acc_num: int, action_descr: str, command: Callable):
        full_action_descr = ' ' + action_descr if action_descr else ''
        self._print_account_full(service, acc_num)
        field_name = input(f"input field{full_action_descr} ['{STOP}' to stop] >> ")

        while field_name != STOP:
            if field_name in self.all_passwords[service][acc_num].keys():
                command(service, acc_num, field_name)
            else:
                print(f"There is no such field = {field_name}")

            self._print_account_full(service, acc_num)
            field_name = input(f"input field{full_action_descr} ['{STOP}' to stop] >> ")
