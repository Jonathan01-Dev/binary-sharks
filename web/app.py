from flask import Flask, flash, redirect, render_template, request, url_for
from pathlib import Path

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'archipel-web-secret'


def make_path(value):
    candidate = Path(value)
    return candidate if candidate.is_absolute() else Path.cwd() / value


def flash_status(success, text):
    flash(text, 'success' if success else 'error')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/share', methods=['GET', 'POST'])
def share():
    if request.method == 'POST':
        filepath = request.form['filepath']
        path = make_path(filepath)
        if path.exists():
            flash_status(True, f'Fichier {path.name} prêt à être partagé.')
        else:
            flash_status(False, f'Le fichier {path} est introuvable.')
        return redirect(url_for('share'))
    return render_template('share.html')


@app.route('/download', methods=['GET', 'POST'])
def download():
    if request.method == 'POST':
        manifest = make_path(request.form['manifest'])
        if manifest.exists():
            flash_status(True, f'Manifeste {manifest.name} prêt pour le download.')
        else:
            flash_status(False, f'Manifeste {manifest} introuvable.')
        return redirect(url_for('download'))
    return render_template('download.html')


@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if request.method == 'POST':
        peer = request.form['peer_id'].strip()
        if peer:
            flash_status(True, 'Message prêt à partir vers le peer')
        else:
            flash_status(False, 'Renseigne un peer ID valide.')
        return redirect(url_for('chat'))
    return render_template('chat.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
