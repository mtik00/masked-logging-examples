#!/usr/bin/env python3
import logging

SENSITIVE: list[str] = []
TIMEZONE: str = "America/Denver"


class Formatter(logging.Formatter):
    def __init__(
        self,
        timezone: str = TIMEZONE,
        fmt="%(asctime)s %(name)s:%(lineno)03d [%(levelname)s] : %(message)s",
        *args,
        **kwargs,
    ):
        self._timezone = timezone

        super().__init__(
            fmt=fmt, datefmt="%m/%d/%Y %H:%M:%S %Z", *args, **kwargs
        )  # type: ignore

    def format(self, record):
        result: str = super().format(record)

        for item in SENSITIVE:
            result = result.replace(item, item[:2] + "*" * 8)

        return result


handler = logging.StreamHandler()
handler.setFormatter(Formatter())
logging.basicConfig(level=logging.INFO, handlers=[handler])


if __name__ == "__main__":
    from getpass import getpass

    log = logging.getLogger("test")

    password = getpass("Enter your secret password:")
    SENSITIVE.append(password)
    log.error("look at my password: %s", password)
