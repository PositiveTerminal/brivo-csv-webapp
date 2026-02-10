import argparse
import asyncio
import logging
import os
from tempfile import mkdtemp

from cachelib import FileSystemCache
from flask import Blueprint, Flask, flash, redirect, render_template
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix

from app.blueprints.auth import auth
from app.blueprints.upload import upload
from app.util import (
    BrivoApiContext,
    EnvKeys,
    MISSING_ENV_VALUE,
    PathNames,
    getenv,
    login_required,
    login_required_async,
    random_string,
    writable_path,
)


def create_app(*args, **kwargs):
    os.umask(0o077)

    app = Flask(__name__, template_folder="templates", static_folder="static")

    app.wsgi_app = ProxyFix(app.wsgi_app)

    app.secret_key = os.urandom(24)
    app.config["PERMANENT_SESSION_LIFETIME"] = 3600
    for var in EnvKeys.all():
        app.config[var] = getenv(var)
    app.config["SESSION_TYPE"] = "cachelib"

    if app.config[EnvKeys.WRITABLE_BASE_PATH] == MISSING_ENV_VALUE:
        app.config[EnvKeys.WRITABLE_BASE_PATH] = mkdtemp()

    app.config['SESSION_CACHELIB'] = FileSystemCache(
        cache_dir=os.path.join(app.config[EnvKeys.WRITABLE_BASE_PATH], PathNames.SESSION_DIR), threshold=500
    )
    Session(app)
    app.register_blueprint(auth)
    app.register_blueprint(main)
    app.register_blueprint(upload)

    return app


def gunicorn_app():
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    gunicorn_logger = logging.getLogger('gunicorn.error')
    root_logger.handlers = gunicorn_logger.handlers
    root_logger.setLevel(gunicorn_logger.level)
    return create_app()


main = Blueprint('main', __name__)


@main.route("/test_api", methods=["GET"])
@login_required_async
async def test_api():
    async def write_test(fpath, name):
        try:
            with open(fpath, "w") as f:
                f.write("Random data\n")
            flash(f"{name} writable", "success")
            os.remove(fpath)
        except Exception as e:
            flash(f"Error while trying to write a file: {e}", "danger")

    async with BrivoApiContext() as brivo:
        try:
            token_response = await brivo.healthcheck()
        except Exception as e:
            # probably too general, but we don't want to return success
            # if api is not working for any reason (network, dns, 50x on brivo side)
            flash(f"API Test failed: {e}", "danger")
        else:
            flash(
                f"API Test passed - code: {token_response.status}. App ready to use",
                "success",
            )

    await asyncio.gather(
        write_test(os.path.join(writable_path(PathNames.UPLOADS_DIR), random_string(16)), "Uploads"),
        write_test(os.path.join(writable_path(PathNames.SESSION_DIR), random_string(16)), "Sessions"),
        write_test(os.path.join(writable_path(PathNames.PROCESSED_DIR), random_string(16)), "Processing"),
    )
    return redirect("/")


@main.route("/")
@login_required
def index():
    return render_template("index.html")


if __name__ == "__main__":  # pragma: no cover
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", default=int(os.environ.get("PORT", 8080)))
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    app = create_app()
    app.run(host=args.host, port=args.port, debug=args.debug)
