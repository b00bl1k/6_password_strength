import getpass
import sys


PASSWORD_STRENGTH_MIN = 1
PASSWORD_STRENGTH_MAX = 10
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 14
PASSWORD_LENGTH_SCORE = 5
PASSWORD_DEFAULT_SCORE = 1


def load_blacklist(filepath):
    with open(filepath, "r", encoding="utf8") as fh:
        return [word.strip().lower() for word in fh.readlines()]


def is_password_use_lower_alpha(password):
    return any(symbol.isalpha() and symbol.islower() for symbol in password)


def is_password_use_upper_alpha(password):
    return any(symbol.isalpha() and symbol.isupper() for symbol in password)


def is_password_use_digits(password):
    return any(symbol.isdigit() for symbol in password)


def is_password_use_spec_symbols(password):
    return any(not symbol.isalnum() for symbol in password)


def is_password_contain_bl_words(password, blacklist):
    lower_password = password.lower()
    return not any(word in lower_password for word in blacklist)


def is_password_recommended_length(password):
    pwd_len = len(password)

    if pwd_len < PASSWORD_MIN_LENGTH:
        return 0

    if pwd_len > PASSWORD_MAX_LENGTH:
        return PASSWORD_LENGTH_SCORE

    len_range = PASSWORD_MAX_LENGTH - PASSWORD_MIN_LENGTH
    return (pwd_len - PASSWORD_MIN_LENGTH) * PASSWORD_LENGTH_SCORE // len_range


def get_password_strength(password, blacklist):
    checks = (
        (is_password_use_lower_alpha, PASSWORD_DEFAULT_SCORE),
        (is_password_use_upper_alpha, PASSWORD_DEFAULT_SCORE),
        (is_password_use_digits, PASSWORD_DEFAULT_SCORE),
        (is_password_use_spec_symbols, PASSWORD_DEFAULT_SCORE),
        (is_password_contain_bl_words, PASSWORD_DEFAULT_SCORE, blacklist),
        (is_password_recommended_length, PASSWORD_LENGTH_SCORE)
    )
    score = sum(map(lambda fn: fn[0](password, *fn[2:]), checks))
    score_max = sum(map(lambda fn: fn[1], checks))

    strength_range = (PASSWORD_STRENGTH_MAX - PASSWORD_STRENGTH_MIN)
    return PASSWORD_STRENGTH_MIN + score * strength_range // score_max


def main():
    try:
        blacklist = load_blacklist(sys.argv[1])
    except IndexError:
        blacklist = []
        print("Blacklist file is not specified!")
    except FileNotFoundError:
        sys.exit("Blacklist file is not found!")
    password = getpass.getpass()
    if not password:
        sys.exit("Password is empty")
    strength = get_password_strength(password, blacklist)
    print("Password strength: {}/{}".format(strength, PASSWORD_STRENGTH_MAX))


if __name__ == '__main__':
    main()
