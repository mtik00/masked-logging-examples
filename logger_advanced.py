#!/usr/bin/env python3
import logging
import re
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Callable, Match, Pattern

SENSITIVE: list[str] = []
TIMEZONE: str = "America/Denver"


@dataclass
class Mask:
    description: str
    pattern: Pattern
    mask_function: Callable


class Masker:
    def __init__(self):
        # WARNING: Order is important!  An email might look a lot like a URI,
        #  depending on how much effort you put into the regex.
        self.mask_config: list[Mask] = [
            Mask(
                "uri_auth",
                re.compile(
                    r"^(?P<protocol>.+?//)(?P<username>.+?):(?P<password>.+?)@(?P<address>.+)$"
                ),
                Masker.hide_uri_auth,
            ),
            Mask(
                "email",
                re.compile(
                    r"""
                        ((?P<username>[a-z0-9!#$%&'*+\/=?^_`{|.}~-]+)
                        @
                        (?P<domain>(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?))
                    """,
                    re.IGNORECASE | re.VERBOSE,
                ),
                Masker.hide_email,
            ),
            Mask(
                "gh_pat",
                re.compile(r"(?P<token>ghp_[0-9a-zA-Z]{36})"),
                Masker.hide_token,
            ),
            Mask(
                "aws_access_key",
                re.compile(
                    r"(?P<token>(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})"
                ),
                Masker.hide_token,
            ),
            Mask(
                "aws_secret_key",
                re.compile(
                    r"(?P<token>aws(.{0,20})?['\\\"][0-9a-zA-Z\/+]{40}['\\\"])",
                    re.IGNORECASE,
                ),
                Masker.hide_token,
            ),
            Mask(
                "basic auth header",
                re.compile(r"basic (?P<token>[a-zA-Z0-9_\-:.=]+)", re.IGNORECASE),
                # For example, maybe we only want starting characters
                partial(Masker.hide_token, end_chars=0),
            ),
        ]

    def mask(self, text: str) -> str:
        """Test the text on all of our defined objects."""
        for mask_obj in self.mask_config:
            # We're using `re.search` instead of `re.match` so we can _easily_
            # pattern-match on substrings and only mask part of the full text.
            if match := mask_obj.pattern.search(text):
                return mask_obj.mask_function(text, match)

        return text

    @staticmethod
    def hide_email(text: str, match: Match) -> str:
        """This is super specific to the Mask object!"""
        email = match.group(0)
        name, domain = match.group("username"), match.group("domain")
        new_name = name[:2] + "*" * 8
        new_email = f"{new_name}@{domain}"
        return text.replace(email, new_email)

    @staticmethod
    def hide_uri_auth(uri: str, match: Match) -> str:
        """This is super specific to the Mask object!"""
        username, password = match.group("username"), match.group("password")

        new_username = username[:2] + "*" * 8
        new_password = password[:2] + "*" * 8

        return uri.replace(f"{username}:{password}", f"{new_username}:{new_password}")

    @staticmethod
    def hide_token(
        text: str,
        match: Match,
        output_chars: int = 8,
        start_chars: int = 4,
        end_chars: int = 4,
    ):
        """This is super specific to the Mask object!
        All tokens pretty much look the same.  The starting characters tend
        to mean something to the API, and the ending characters tend to be unique.
        """
        token = match.group("token")
        stars = "*" * max((output_chars - start_chars - end_chars), output_chars)
        new_token = (
            token[:start_chars] + stars + token[len(token) - end_chars :]  # noqa: E203
        )
        return text.replace(token, new_token)


class Formatter(logging.Formatter):
    def __init__(
        self,
        timezone: str = TIMEZONE,
        fmt="%(asctime)s %(name)s:%(lineno)03d [%(levelname)s] : %(message)s",
        *args,
        **kwargs,
    ):
        self._masker = Masker()
        self._timezone = timezone

        super().__init__(
            fmt=fmt, datefmt="%m/%d/%Y %H:%M:%S %Z", *args, **kwargs
        )  # type: ignore

    def format(self, record):
        result: str = super().format(record)

        for item in SENSITIVE:
            result = result.replace(item, item[:2] + "*" * 8)

        result = self._masker.mask(result)

        return result


def set_root_level(level):
    logging.getLogger().setLevel(level)


def init_logger(level: int = logging.INFO):
    handler = logging.StreamHandler()
    handler.setFormatter(Formatter())
    logging.basicConfig(level=level, handlers=[handler])


def add_log_file(filename: str | Path, level: int = logging.DEBUG):
    # Python logging is tricky.  The root logger has to be set to the lowest
    # level needed.  However, you don't neccessarily want to set the log level
    # for _everything_ (setting the root logger to `DEBUG` can set many library
    # loggers to `DEBUG` as well).
    root = logging.getLogger()
    if level < root.level:
        for handler in [x for x in root.handlers if not x.level]:
            handler.setLevel(root.level)

        root.setLevel(level)

    handler = logging.FileHandler(filename)
    handler.setFormatter(Formatter())
    handler.setLevel(level)
    logging.getLogger().addHandler(handler)


if __name__ == "__main__":
    import logging

    init_logger()

    log = logging.getLogger("test")

    password = "mypasswordis1234"

    # Add sensitive strings directly
    SENSITIVE.append(password)
    log.error("look at my password: %s", password)

    # Use the pre-compiled regexes to hide URL authentication
    url = "https://myuser:mypassword@github.com/myuser/repos/project1"
    log.warning("Can't connect to: %s", url)

    email = "test@testing.com"
    log.info("Invalid email: %s", email)

    github_pat = "ghp_tcneoh887ypmz96yhyu085o8500cuxis40wv"
    log.info("bad GitHub personal access token: %s", github_pat)

    basic_auth_header = {"Authorization": "Basic dGVzdC1wYXNzd29yZA=="}
    log.info("request headers: %s", basic_auth_header)

    try:
        raise ValueError(f"headers: {basic_auth_header}")
    except Exception:
        log.exception("request headers: %s", basic_auth_header, exc_info=True)
        # THIS WILL LEAK SENSITIVE INFORMATION!
        raise
