from calculator import add, multiply  # type: ignore[import-not-found]

raise SystemExit(0 if add(2, 3) == 5 and multiply(2, 3) == 6 else 1)
