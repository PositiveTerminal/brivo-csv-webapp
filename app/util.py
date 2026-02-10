import csv
import logging
import os
import random
import string
from functools import wraps

from flask import current_app, redirect, request, session

MISSING_ENV_VALUE = "MISSING"

class KeysBase:
    @classmethod
    def all(cls):
        return set([v for k, v in cls.__dict__.items() if isinstance(v, str) and k.isupper()])


class PathNames(KeysBase):
    UPLOADS_DIR = "uploads"
    SESSION_DIR = "flask_session"
    PROCESSED_DIR = "processed"


class EnvKeys(KeysBase):
    APIKEY = "BRIVO_APIKEY"
    CLIENT_ID = "BRIVO_CLIENT_ID"
    CLIENT_SECRET = "BRIVO_CLIENT_SECRET"
    REDIRECT_URI = "BRIVO_REDIRECT_URI"
    WRITABLE_BASE_PATH = "WRITABLE_BASE_PATH"


log = logging.getLogger(__name__)


def writable_path(element):
    path = os.path.join(current_app.config[EnvKeys.WRITABLE_BASE_PATH], element)
    os.makedirs(path, exist_ok=True)
    return path


def random_string(length: int = 32) -> str:
    char_set = string.ascii_lowercase + string.ascii_uppercase + string.digits
    return "".join([random.choice(char_set) for i in range(length)])


def getenv(key, default=MISSING_ENV_VALUE):
    return os.environ.get(key, default)


def gen_batches(iterable, n=1):
    length = len(iterable)
    for ndx in range(0, length, n):
        yield iterable[ndx : min(ndx + n, length)]


def sanitize_form():
    form = {}
    for k, v in request.form.items():
        form[k] = v.strip()
    return form


def check_csv_header(file_path, typ):
    from app.processing import EXPECTED_CSV_HEADERS

    with open(file_path, "r") as f:
        reader = csv.DictReader(f)
        header_diff = set(reader.fieldnames).difference(EXPECTED_CSV_HEADERS[typ])  # type: ignore
        if header_diff:
            return False, header_diff
    return True, None


def user_is_authenticated():
    return "username" in session and "token_object" in session


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not user_is_authenticated():
            return redirect("/login")
        ret = f(*args, **kwargs)

        return ret

    return decorated_function


def login_required_async(func):
    @wraps(func)
    async def decorated_function(*args, **kwargs):
        if not user_is_authenticated():
            return redirect("/login")
        return await func(*args, **kwargs)

    return decorated_function


def is_input_true(input):
    return input.lower() in ["true", "1", "yes", "y"]


def valid_config_found():
    return all([current_app.config[k] != MISSING_ENV_VALUE for k in EnvKeys.all()])


class BrivoApiContext:
    def __init__(self):
        # circular import
        from app.brivo import BrivoApi

        self.brivo = BrivoApi(
            api_key=current_app.config[EnvKeys.APIKEY],
            client_id=current_app.config[EnvKeys.CLIENT_ID],
            client_secret=current_app.config[EnvKeys.CLIENT_SECRET],
            redirect_uri=current_app.config[EnvKeys.REDIRECT_URI],
            token_data=session.get("token_object"),  # type: ignore
        )

    async def __aenter__(self):
        return self.brivo

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.brivo.close()
        # HACK: horrible hack of refreshing the token object
        session["token_object"] = self.brivo.get_token_data()  # type: ignore
