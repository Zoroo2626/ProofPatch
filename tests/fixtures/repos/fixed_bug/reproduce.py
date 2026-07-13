from calculator import add  # type: ignore[import-not-found]

actual = add(2, 3)
print(f"add(2, 3)={actual}")
raise SystemExit(0 if actual == 5 else 1)
