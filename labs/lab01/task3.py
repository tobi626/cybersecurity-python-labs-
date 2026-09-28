import csv
import hashlib
import json
import os
import sys
from datetime import datetime
from functools import wraps

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from shared.student import (
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT_NUMBER,
)


HASH_ALGORITHM = "blake2s" 
MIN_PASSWORD_LENGTH = 9  
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")

users_to_register = (
    ("red_team_lead", "R3dTeam@2024"),
    ("blue_team_analyst", "Blu3Team!Sec"),
    ("purple_team_coord", "Purpl3#Coord"),
    ("student_intern", "Stud3nt@KB203"),
    ("soc_monitor", "S0cM0nitor!"),
    ("pentester_01", "P3nt3st#2024"),
    ("crypto_expert", "Crypt0@Expert"),
    ("audit_officer", "Aud1t&Officer"),
    ("lab_assistant", "L4bAssist!23"),
    ("guest_researcher", "Gu3st@Research"),
)

users_db = []


class ValidationError(Exception):
    pass

def generate_hash(password: str, salt: str = "00000") -> str:
    if password is None or password == "":
        raise ValueError("Пароль не може бути порожнім")
    if salt is None or salt == "":
        raise ValueError("Сіль не може бути порожньою")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль коротший за мінімальну довжину "
            f"({MIN_PASSWORD_LENGTH} символів)"
        )

    hash_object = hashlib.new(HASH_ALGORITHM)
    hash_object.update((password + salt).encode("utf-8"))
    return hash_object.hexdigest()


def create_user(username, password):
    hash_value = generate_hash(password, PERSONAL_SALT)
    return (username, hash_value)


def create_users(users_list):
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

    prepared_users = []
    for username, password in users_list:
        try:
            user_record = create_user(username, password)
            prepared_users.append(user_record)
            print(f"    Зареєстровано користувача: {username}")
        except ValidationError as error:
            print(f"    ValidationError ({username}): {error}")
        except ValueError as error:
            print(f"    ValueError ({username}): {error}")

    try:
        with open(USERS_CSV_PATH, "w", newline="", encoding="utf-8") as file:
            csv_writer = csv.writer(file)
            for user_record in prepared_users:
                csv_writer.writerow(user_record)
        print(f"    Базу збережено у файл: {USERS_CSV_PATH}")
    except FileNotFoundError as error:
        print(f"    Файл не знайдено: {error}")
    except PermissionError as error:
        print(f"    Немає прав доступу до файлу: {error}")
    except IOError as error:  
        print(f"    Помилка вводу/виводу: {error}")



def read_users_db():
    users_list = []
    try:
        with open(USERS_CSV_PATH, "r", newline="", encoding="utf-8") as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                username = row[0]
                hash_value = row[1]
                users_list.append([username, hash_value])
    except FileNotFoundError:
        print("    Файл users.csv не знайдено. Спочатку створіть базу.")
    except PermissionError as error:
        print(f"    Немає прав доступу до файлу: {error}")
    except IOError as error:  
        print(f"    Помилка вводу/виводу: {error}")
    return users_list


def print_users_db(users_list):
    print(f"{'No':<4}{'Логін':<22}{'Хеш пароля (blake2s + сіль)':<66}")

    number = 1
    for row in users_list:
        username = row[0]
        hash_value = row[1]
        print(f"{number:<4}{username:<22}{hash_value:<66}")
        number = number + 1

    print(f"Усього записів у базі: {len(users_list)}")



def write_log(event_record):
    events = []

    try:
        with open(LOG_JSON_PATH, "r", encoding="utf-8") as file:
            events = json.load(file)
    except FileNotFoundError:
        events = []  
    except PermissionError as error:
        print(f"    Немає прав доступу до журналу: {error}")
        return
    except IOError as error: 
        print(f"    Помилка вводу/виводу журналу: {error}")
        return
    except ValueError:
        events = []  

    events.append(event_record)

    try:
        with open(LOG_JSON_PATH, "w", encoding="utf-8") as file:
            json.dump(events, file, ensure_ascii=False, indent=4)
    except PermissionError as error:
        print(f"    Немає прав доступу до журналу: {error}")
    except IOError as error:  
        print(f"    Помилка вводу/виводу журналу: {error}")


def log_event(func):

    @wraps(func)
    def wrapper(*args, **kwargs):
        login_result = func(*args, **kwargs)

        if login_result:
            event_result = "success"
        else:
            event_result = "failure"

        if "username" in kwargs:
            event_user = kwargs["username"]
        elif len(args) > 0:
            event_user = args[0]
        else:
            event_user = "unknown"

        current_time = datetime.now() 
        event_time = current_time.strftime("%Y-%m-%d %H:%M:%S")

        event_record = {
            "event": "login",
            "user": event_user,
            "result": event_result,
            "timestamp": event_time,
            "args": [],
            "kwargs": {},
        }
        write_log(event_record)

        return login_result

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    if username is None or username == "":
        raise ValueError("Логін не може бути порожнім")
    if password is None or password == "":
        raise ValueError("Пароль не може бути порожнім")

    for row in users_db:
        if row[0] == username:
            stored_hash = row[1]
            entered_hash = generate_hash(password, PERSONAL_SALT)
            if stored_hash == entered_hash:  
                return True
            return False

    return False


def print_log():
    try:
        with open(LOG_JSON_PATH, "r", encoding="utf-8") as file:
            events = json.load(file)
    except FileNotFoundError:
        print("    Журнал подій ще не створено.")
        return
    except PermissionError as error:
        print(f"    Немає прав доступу до журналу: {error}")
        return
    except IOError as error:  
        print(f"    Помилка вводу/виводу журналу: {error}")
        return

    for event in events:
        print("    " + json.dumps(event, ensure_ascii=False))


def main():
    global users_db

    print("Завдання 3. Хешування, CSV-база та JSON-логування")

    print(f"Студент : {STUDENT_NAME}")
    print(f"Група   : {GROUP_NAME}")
    print(f"Варіант : {VARIANT_NUMBER}")
    print(f"Алгоритм хешування      : {HASH_ALGORITHM}")
    print(f"Мінімальна довжина пароля: {MIN_PASSWORD_LENGTH}")
    print(f"Персональна сіль        : {PERSONAL_SALT}")
    print()

    print("1) Реєстрація користувачів (users_to_register):")
    try:
        create_users(users_to_register)
    except ValidationError as error:
        print(f"    ValidationError: {error}")
    except ValueError as error:
        print(f"    ValueError: {error}")
    except PermissionError as error:
        print(f"    Немає прав доступу: {error}")
    except IOError as error:  
        print(f"    Помилка вводу/виводу: {error}")
    print()

    print("2) Читання бази користувачів з файла users.csv:")
    users_db = read_users_db()
    print_users_db(users_db)
    print()

    print("3) Автентифікація користувачів (функція login):")

    try:
        result = login("red_team_lead", "R3dTeam@2024")
        print(f"    login('red_team_lead', правильний пароль) -> {result}")
    except (ValidationError, ValueError) as error:
        print(f"    Помилка входу: {error}")

    try:
        result = login("blue_team_analyst", "WrongPass!2024")
        print(f"    login('blue_team_analyst', хибний пароль)  -> {result}")
    except (ValidationError, ValueError) as error:
        print(f"    Помилка входу: {error}")

    try:
        result = login("hacker_999", "H4ck3r@Pass")
        print(f"    login('hacker_999', немає в базі)         -> {result}")
    except (ValidationError, ValueError) as error:
        print(f"    Помилка входу: {error}")

    try:
        result = login("student_intern", "short")
        print(f"    login('student_intern', 'short')          -> {result}")
    except ValidationError as error:
        print(f"    Перехоплено ValidationError: {error}")
    except ValueError as error:
        print(f"    Перехоплено ValueError: {error}")

    try:
        result = login("student_intern", "")
        print(f"    login('student_intern', '')               -> {result}")
    except ValidationError as error:
        print(f"    Перехоплено ValidationError: {error}")
    except ValueError as error:
        print(f"    Перехоплено ValueError: {error}")

    print()
    print("4) Обробка винятку FileNotFoundError (файла немає):")
    missing_db = read_missing_file()
    print(f"    Результат читання відсутнього файла: {missing_db}")
    print()

    print("5) Журнал подій авторизації (data/log.json):")
    print_log()


def read_missing_file():
    missing_path = os.path.join(DATA_DIR, "missing_file.csv")
    try:
        with open(missing_path, "r", encoding="utf-8") as file:
            return file.read()
    except FileNotFoundError as error:
        print(f"    Перехоплено FileNotFoundError: {error}")
        return None
    except PermissionError as error:
        print(f"    Немає прав доступу до файлу: {error}")
        return None
    except IOError as error:  
        print(f"    Помилка вводу/виводу: {error}")
        return None


if __name__ == "__main__":
    main()
