"""Target bug fixed while unrelated multiplication is regressed."""


def add(left: int, right: int) -> int:
    return left + right


def multiply(left: int, right: int) -> int:
    return left + right
