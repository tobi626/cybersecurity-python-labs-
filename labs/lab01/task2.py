import os
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from shared.student import (
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT_NUMBER,
)


users = {
    "red_team_lead": {
        "role": "red_team",
        "clearance": 4,
        "department": "Red Team",
        "active": True,
    },
    "blue_team_analyst": {
        "role": "blue_team",
        "clearance": 3,
        "department": "Blue Team",
        "active": True,
    },
    "purple_team_coord": {
        "role": "purple_team",
        "clearance": 3,
        "department": "Purple Team",
        "active": True,
    },
    "student_intern": {
        "role": "student",
        "clearance": 1,
        "department": "Academia",
        "active": True,
    },
    "retired_expert": {
        "role": "retired",
        "clearance": 2,
        "department": "Emeritus",
        "active": False,
    },
}

resources = [
    ("attack_scenarios", 4),
    ("defense_playbooks", 3),
    ("exercise_plans", 3),
    ("research_papers", 1),
    ("exploit_tools", 4),
    ("student_resources", 1),
    ("simulation_results", 3),
    ("red_team_tools", 4),
    ("blue_team_reports", 3),
    ("public_research", 1),
]

security_levels = ("Academic", "Operational", "Tactical", "Strategic")

blocked_users = {"retired_expert", "academic_violator", "leaked_account"}


def get_level_name(resource_level):
    index = resource_level - 1
    if index < 0 or index >= len(security_levels):
        return "Unknown"
    return security_levels[index]


def check_access(username, resource_name, resource_level):
    if username not in users:
        return False, "User not found"
    
    if username in blocked_users:
        return False, "User is blocked"

    if users[username]["active"] is False:
        return False, "Account inactive"

    clearance = users[username]["clearance"]
    if clearance >= resource_level:
        return True, ""

    return False, "Insufficient clearance"


def print_resources():
    print("Список усіх ресурсів системи:")
    print(f"{'No':<4}{'Ресурс':<24}{'Рівень безпеки':<16}")
    number = 1
    for resource_name, resource_level in resources:
        level_name = get_level_name(resource_level)
        row = f"{number:<4}{resource_name:<24}{level_name:<16}"
        print(row)
        number = number + 1


def print_users_info():
    print("Користувачі системи:")
    header = (
        f"{'Логін':<22}{'Роль':<14}{'Департамент':<14}"
        f"{'Допуск':<9}{'Активний':<9}"
    )
    print(header)

    for username, user_info in users.items():
        active = str(user_info["active"])
        row = (
            f"{username:<22}{user_info['role']:<14}"
            f"{user_info['department']:<14}"
            f"{user_info['clearance']:<9}{active:<9}"
        )
        print(row)


def print_access_results():
    print("Результати перевірки доступу:")
    print()

    allow_count = 0
    deny_count = 0

    for username in users:
        for resource_name, resource_level in resources:
            allowed, reason = check_access(
                username, resource_name, resource_level
            )
            if allowed:
                allow_count = allow_count + 1
                print(f"user={username} resource={resource_name} -> ALLOW")
            else:
                deny_count = deny_count + 1
                print(
                    f"user={username} resource={resource_name} "
                    f"-> DENY ({reason})"
                )
        print()

    print(f"Усього дозволів (ALLOW): {allow_count}")
    print(f"Усього відмов (DENY)  : {deny_count}")


def main():
    print("Завдання 2. Багаторівнева система контролю доступу")

    print(f"Студент : {STUDENT_NAME}")
    print(f"Група   : {GROUP_NAME}")
    print(f"Варіант : {VARIANT_NUMBER}")
    print()

    print_users_info()
    print()

    print("Заблоковані користувачі (blocked_users):")
    for blocked in sorted(blocked_users):
        print(f"    {blocked}")
    print()

    print_resources()
    print()

    print("Текстові назви рівнів безпеки (security_levels):")
    level_number = 1
    for level_name in security_levels:
        print(f"    {level_number} -> {level_name}")
        level_number = level_number + 1
    print()

    print_access_results()


if __name__ == "__main__":
    main()
