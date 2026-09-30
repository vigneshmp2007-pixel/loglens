import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    # Debug mode exposes the Werkzeug debugger (remote code execution), so it is
    # opt-in and the server binds to localhost unless you explicitly change it.
    app.run(
        host=os.environ.get("LOGLENS_HOST", "127.0.0.1"),
        port=int(os.environ.get("LOGLENS_PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
