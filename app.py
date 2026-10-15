from pathlib import Path
import logging
import re
from werkzeug.serving import WSGIRequestHandler

from flask import Flask, render_template
from flask_wtf.csrf import CSRFProtect

from config import Config
from secure_gateway.auth import auth_bp
from secure_gateway.dashboard import dashboard_bp
from secure_gateway.delete import delete_bp
from secure_gateway.download import download_bp
from secure_gateway.upload import upload_bp
from secure_gateway.rescan import rescan_bp
from secure_gateway.sharing import sharing_bp


class RedactingRequestHandler(WSGIRequestHandler):
    """Redact bearer tokens from local Werkzeug access logs."""

    def log_request(self, code="-", size="-"):
        request_line = getattr(self, "requestline", "")

        request_line = re.sub(
            r"(/shared/)[^?\s]+",
            r"\1[REDACTED]",
            request_line,
        )

        self.log(
            "info",
            '"%s" %s %s',
            request_line,
            code,
            size,
        )

def create_app():
    Config.validate()

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    app.config.from_object(Config)

    # ---------------------------------------------------------
    # Security
    # ---------------------------------------------------------
    csrf = CSRFProtect()
    csrf.init_app(app)

    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = Config.SESSION_COOKIE_SECURE

    # Maximum upload request size
    app.config["MAX_CONTENT_LENGTH"] = Config.MAX_FILE_SIZE

    # ---------------------------------------------------------
    # Required directories
    # ---------------------------------------------------------
    Path(app.config["UPLOAD_FOLDER"]).mkdir(
        parents=True,
        exist_ok=True,
    )

    Path(app.config["ENCRYPTED_FOLDER"]).mkdir(
        parents=True,
        exist_ok=True,
    )

    Path(app.config["QUARANTINE_FOLDER"]).mkdir(
        parents=True,
        exist_ok=True,
    )

    Path("logs").mkdir(
        parents=True,
        exist_ok=True,
    )

    # ---------------------------------------------------------
    # Application logging
    # ---------------------------------------------------------
    log_file = Path("logs") / "secure_gateway.log"

    file_handler = logging.FileHandler(
        log_file,
        encoding="utf-8",
    )

    file_handler.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    file_handler.setFormatter(formatter)

    if not any(
        isinstance(handler, logging.FileHandler)
        and getattr(handler, "baseFilename", None)
        == str(log_file.resolve())
        for handler in app.logger.handlers
    ):
        app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)

    # ---------------------------------------------------------
    # Blueprints
    # ---------------------------------------------------------
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(delete_bp) 
    app.register_blueprint(download_bp)
    app.register_blueprint(upload_bp)
    app.register_blueprint(rescan_bp)
    app.register_blueprint(sharing_bp)
    # ---------------------------------------------------------
    # Routes
    # ---------------------------------------------------------
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/terms")
    def terms():
        return render_template("terms.html")

    # ---------------------------------------------------------
    # Error handlers
    # ---------------------------------------------------------
    @app.errorhandler(400)
    def bad_request(error):
        app.logger.warning(
            "400 Bad Request | path=%s",
            getattr(error, "description", "unknown"),
        )

        return render_template(
            "error.html",
            status_code=400,
            message="The request could not be processed.",
        ), 400

    @app.errorhandler(403)
    def forbidden(error):
        app.logger.warning(
            "403 Forbidden | path=%s",
            getattr(error, "description", "unknown"),
        )

        return render_template(
            "error.html",
            status_code=403,
            message="You do not have permission to access this resource.",
        ), 403

    @app.errorhandler(404)
    def page_not_found(error):
        return render_template(
            "error.html",
            status_code=404,
            message="The requested page could not be found.",
        ), 404

    @app.errorhandler(413)
    def request_entity_too_large(error):
        app.logger.warning(
            "413 Request Entity Too Large"
        )

        return render_template(
            "error.html",
            status_code=413,
            message="The uploaded file is too large.",
        ), 413

    @app.errorhandler(500)
    def internal_server_error(error):
        app.logger.exception(
            "500 Internal Server Error"
        )

        return render_template(
            "error.html",
            status_code=500,
            message="An unexpected server error occurred.",
        ), 500

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        request_handler=RedactingRequestHandler,
    )