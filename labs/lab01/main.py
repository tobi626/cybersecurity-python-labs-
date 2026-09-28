import os
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

import task1
import task2
import task3

from shared.student import (
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT_NUMBER,
)


def main():

    print("# ЛАБОРАТОРНА РОБОТА №1")
    print("# Тема: Основи розробки на Python, Git та стандарти стилю коду")
    print(f"Виконав : {STUDENT_NAME}")
    print(f"Група   : {GROUP_NAME}")
    print(f"Варіант : {VARIANT_NUMBER}")
    print()

    task1.main()
    print()

    task2.main()
    print()

    task3.main()
    print()

    print("# Усі завдання лабораторної роботи №1 виконано.")


if __name__ == "__main__":
    main()
