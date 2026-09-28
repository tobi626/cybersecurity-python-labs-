import os
import random
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from shared.student import (
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT_NUMBER,
)


passwords = [
    "InfoS3c@2023",
    "simple123",
    "Def3ns3@Key",
    "public",
    "Encrypt3d#Pass",
    "basic123",
    "Secur3@Analysis",
    "temp123",
    "Pr0t3ct@Data",
    "default",
]

criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {
    "simple123",
    "public",
    "basic123",
    "temp123",
    "default",
    "guest",
}


def has_digit(password):
    for symbol in password:
        if symbol.isdigit():
            return True
    return False


def has_upper(password):
    for symbol in password:
        if symbol.isupper():
            return True
    return False


def has_lower(password):
    for symbol in password:
        if symbol.islower():
            return True
    return False


def has_special(password):
    for symbol in password:
        if not symbol.isalnum():
            return True
    return False


def count_met_criteria(password, criteria):
    met_count = 0
    total_count = 0

    if criteria["require_digits"]:
        total_count = total_count + 1
        if has_digit(password):
            met_count = met_count + 1

    if criteria["require_upper"]:
        total_count = total_count + 1
        if has_upper(password):
            met_count = met_count + 1

    if criteria["require_special"]:
        total_count = total_count + 1
        if has_special(password):
            met_count = met_count + 1

    return met_count, total_count


def password_marks(password):
    marks = ""
    if has_digit(password):
        marks = marks + "D" 
    if has_upper(password):
        marks = marks + "U"  
    if has_lower(password):
        marks = marks + "L" 
    if has_special(password):
        marks = marks + "S"  
    return marks


def add_duplicates(passwords):
    random_indexes = []
    counter = 0

    while counter < 3:
        random_index = random.randint(0, len(passwords) - 1)
        random_indexes.append(random_index)
        counter = counter + 1

    for random_index in random_indexes:
        passwords.append(passwords[random_index])

    return random_indexes


def check_password(password, all_passwords, criteria, forbidden_passwords):
    min_length = criteria["min_length"]

    if password in forbidden_passwords:
        return "Заборонений"

    if len(password) < min_length:
        return "Заборонений"

    met_count, total_count = count_met_criteria(password, criteria)

    is_unique = True
    if all_passwords.count(password) > 1:
        is_unique = False

    if met_count == total_count:
        if len(password) >= min_length + 4 and is_unique:
            return "Дуже сильний"
        return "Сильний"

    if met_count > 0:
        return "Середній"

    return "Слабкий"


def print_analysis_table(analysis_results):
    header = (
        f"{'No':<4}{'Пароль':<20}{'Довжина':<9}"
        f"{'Символи':<9}{'Рівень надійності':<17}"
    )
    print(header)

    number = 1
    for password, length, marks, strength in analysis_results:
        row = f"{number:<4}{password:<20}{length:<9}{marks:<9}{strength:<17}"
        print(row)
        number = number + 1


def print_statistics(analysis_results):
    levels = [
        "Заборонений",
        "Слабкий",
        "Середній",
        "Сильний",
        "Дуже сильний",
    ]

    print("Статистика за рівнями надійності:")
    for level in levels:
        count = 0
        for password, length, marks, strength in analysis_results:
            if strength == level:
                count = count + 1
        print(f"    {level:<15} : {count}")


def main():

    print("Завдання 1. Комплексний аналізатор надійності паролів")

    print(f"Студент : {STUDENT_NAME}")
    print(f"Група   : {GROUP_NAME}")
    print(f"Варіант : {VARIANT_NUMBER}")
    print()

    print("Критерії безпеки (criteria):")
    for key, value in criteria.items():
        print(f"    {key} = {value}")
    print()

    print("Заборонені паролі (forbidden_passwords):")
    for forbidden in sorted(forbidden_passwords):
        print(f"    {forbidden}")
    print()

    print("Вихідний список паролів (passwords):")
    index = 0
    while index < len(passwords):
        print(f"    [{index}] {passwords[index]}")
        index = index + 1
    print()

    random_indexes = add_duplicates(passwords)
    print("Згенеровані випадкові індекси:", random_indexes)
    print("Паролі-дублікати, додані в кінець списку:")
    for random_index in random_indexes:
        print(f"    індекс {random_index} -> {passwords[random_index]}")
    print(f"Усього паролів для аналізу: {len(passwords)}")
    print()

    analysis_results = []
    for password in passwords:
        strength = check_password(
            password, passwords, criteria, forbidden_passwords
        )
        length = len(password)
        marks = password_marks(password)
        analysis_results.append((password, length, marks, strength))

    print("РЕЗУЛЬТАТ АНАЛІЗУ НАДІЙНОСТІ ПАРОЛІВ")
    print_analysis_table(analysis_results)
    print()
    print("Позначки груп символів: D - цифри, U - великі літери,")
    print("                        L - малі літери, S - спецсимволи")
    print()
    print_statistics(analysis_results)


if __name__ == "__main__":
    main()
