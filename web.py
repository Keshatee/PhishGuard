"""Local browser dashboard for PhishGuard."""

from pathlib import Path
from tempfile import NamedTemporaryFile

from flask import Flask, render_template, request

from cli import analyze_file

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    filename = None
    error = None

    if request.method == "POST":
        uploaded = request.files.get("email")
        if not uploaded or not uploaded.filename:
            error = "Choose an .eml file first."
        elif not uploaded.filename.lower().endswith(".eml"):
            error = "PhishGuard accepts .eml files only."
        else:
            filename = uploaded.filename
            temporary_path = None
            try:
                with NamedTemporaryFile(suffix=".eml", delete=False) as temporary:
                    uploaded.save(temporary)
                    temporary_path = Path(temporary.name)
                report, _, _ = analyze_file(temporary_path)
            except Exception as exc:
                error = f"Could not analyze this email: {exc}"
            finally:
                if temporary_path:
                    temporary_path.unlink(missing_ok=True)

    return render_template("index.html", report=report, filename=filename, error=error)


if __name__ == "__main__":
    app.run(debug=True)
