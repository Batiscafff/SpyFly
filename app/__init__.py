from flask import Flask
from config import Config


def create_app():
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.from_object(Config)

    from app.routes import bp
    app.register_blueprint(bp)

    from app import settings_store
    settings_store.load(app)

    return app
