from flask import Flask, jsonify


def create_app():
    # Imports are kept inside the factory so parser/detector can be imported
    # (and unit-tested) without flask-cors being installed.
    from flask_cors import CORS
    from .routes import api

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    app.register_blueprint(api, url_prefix="/api")

    @app.errorhandler(413)
    def too_large(_):
        return jsonify({"error": "File too large (max 1 GB)"}), 413

    @app.errorhandler(500)
    def server_error(_):
        return jsonify({"error": "Internal server error"}), 500

    return app
