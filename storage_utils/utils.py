import os
from enum import Enum
from typing import List


class Status(Enum):
    NOERROR = 0
    ERROR = 1


def is_file(file_path: str) -> bool:
    return os.path.isfile(file_path)


def is_key_path_correct(key_path: str) -> bool:
    return type(key_path) is str and is_file(key_path)


def get_str_from_num(max_len: int, num: int) -> str:
    return "0"*(max_len - len(str(num))) + str(num)


def get_text_from_list_of_nums(list_of_nums: List[int]) -> str:
    str_nums = ''.join([chr(num) for num in list_of_nums if num != 0])
    return str_nums
