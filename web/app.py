import re
import subprocess
import sys
import threading
import time
from pathlib import Path

from flask import Flask, flash, jsonify, redirect, render_template, request, url_for

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'archipel-web-secret'

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNNING_NODES: dict[int, subprocess.Popen] = {}
MESSAGE_LOCK = threading.Lock()
CHAT_MESSAGES: list[dict] = []
MAX_CHAT_MESSAGES = 200

CHAT_RECV_RE = re.compile(r'^\[(?:UDP-)?CHAT\]\s+recv\s+(.+?)\s+\|\s+(.+?)\s+says:\s+(.*)$')


def make_path(value: str) -> Path:
    candidate = Path(value)
    return candidate if candidate.is_absolute() else PROJECT_ROOT / value


def flash_status(success: bool, text: str) -> None:
    flash(text, 'success' if success else 'error')


def run_command(args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, '-u', str(PROJECT_ROOT / 'main.py'), *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def add_chat_message(direction: str, text: str, peer: str = '', port: int | None = None) -> None:
    item = {
        'ts': int(time.time() * 1000),
        'direction': direction,
        'peer': peer,
        'port': port,
        'text': text,
    }
    with MESSAGE_LOCK:
        CHAT_MESSAGES.append(item)
        if len(CHAT_MESSAGES) > MAX_CHAT_MESSAGES:
            del CHAT_MESSAGES[: len(CHAT_MESSAGES) - MAX_CHAT_MESSAGES]


def _node_output_reader(port: int, proc: subprocess.Popen) -> None:
    if not proc.stdout:
        return
    for raw_line in proc.stdout:
        line = raw_line.strip()
        m = CHAT_RECV_RE.match(line)
        if m:
            add_chat_message('in', m.group(3), peer=m.group(2), port=port)


def start_node_process(port_local: int, shared_file: Path | None = None) -> subprocess.Popen:
    cmd = [
        sys.executable,
        '-u',
        str(PROJECT_ROOT / 'main.py'),
        'start',
        '--port',
        str(port_local),
    ]
    if shared_file is not None:
        cmd.extend(['--share', str(shared_file)])

    proc = subprocess.Popen(
        cmd,
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    RUNNING_NODES[port_local] = proc
    threading.Thread(target=_node_output_reader, args=(port_local, proc), daemon=True).start()
    return proc


def ensure_node_running(port_local: int) -> bool:
    existing = RUNNING_NODES.get(port_local)
    return bool(existing and existing.poll() is None)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/share', methods=['GET', 'POST'])
def share():
    if request.method == 'POST':
        filepath = request.form['filepath']
        port_local = int(request.form.get('port_local', '7902'))
        path = make_path(filepath)

        if not path.exists():
            flash_status(False, f'Le fichier {path} est introuvable.')
            return redirect(url_for('share'))

        if ensure_node_running(port_local):
            flash_status(True, f'Node deja actif sur le port {port_local}.')
            return redirect(url_for('share'))

        proc = start_node_process(port_local, shared_file=path)
        RUNNING_NODES[port_local] = proc
        flash_status(True, f'Node lance sur {port_local} pour partager {path.name} (pid={proc.pid}).')
        return redirect(url_for('share'))
    return render_template('share.html')


@app.route('/stop-node', methods=['POST'])
def stop_node():
    port_local = int(request.form.get('port_local', '0'))
    proc = RUNNING_NODES.get(port_local)
    if not proc or proc.poll() is not None:
        flash_status(False, f'Aucun node actif sur le port {port_local}.')
        return redirect(url_for('share'))
    proc.terminate()
    flash_status(True, f'Node arrete sur le port {port_local}.')
    return redirect(url_for('share'))


@app.route('/download', methods=['GET', 'POST'])
def download():
    if request.method == 'POST':
        manifest = make_path(request.form['manifest'])
        port_local = int(request.form.get('port_local', '7903'))
        transport = request.form.get('transport', 'tcp')

        if not manifest.exists():
            flash_status(False, f'Manifeste {manifest} introuvable.')
            return redirect(url_for('download'))

        try:
            result = run_command(
                [
                    'download',
                    str(manifest),
                    '--port',
                    str(port_local),
                    '--transport',
                    transport,
                ],
                timeout=180,
            )
        except subprocess.TimeoutExpired:
            flash_status(False, 'Download timeout: relance avec un manifeste/peer valide.')
            return redirect(url_for('download'))

        if result.returncode == 0:
            flash_status(True, 'Download termine. Verifie le dossier downloads/.')
        else:
            lines = (result.stderr or result.stdout or '').strip().splitlines()
            details = lines[-1] if lines else 'Erreur inconnue'
            flash_status(False, f'Download echoue: {details}')
        return redirect(url_for('download'))
    return render_template('download.html')


@app.route('/chat', methods=['GET', 'POST'])
def chat():
    default_port = 7904
    if request.method == 'POST':
        peer = request.form.get('peer_id', '').strip()
        message = request.form.get('message', '').strip()
        port_local = int(request.form.get('port_local', str(default_port)))
        peer_port = request.form.get('peer_port', '').strip()
        peer_ip = request.form.get('peer_ip', '').strip()

        if not peer or not message:
            flash_status(False, 'Renseigne un peer ID et un message valides.')
            return redirect(url_for('chat'))

        if not ensure_node_running(port_local):
            proc = start_node_process(port_local)
            flash_status(True, f'Listener chat lance sur {port_local} (pid={proc.pid}).')

        cmd = ['msg', peer, message, '--port', str(port_local)]
        if peer_port:
            cmd.extend(['--peer-port', peer_port])
        if peer_ip:
            cmd.extend(['--peer-ip', peer_ip])

        try:
            result = run_command(cmd, timeout=90)
        except subprocess.TimeoutExpired:
            flash_status(False, 'Envoi message timeout.')
            return redirect(url_for('chat'))

        if result.returncode == 0:
            stdout = result.stdout or ''
            delivered = 'ack=OK' in stdout
            add_chat_message('out', message, peer=peer, port=port_local)
            if delivered:
                add_chat_message('in', f'ACK recu du pair pour: {message}', peer=peer, port=port_local)
                flash_status(True, 'Message envoye et recu par le pair (ack=OK).')
            else:
                flash_status(True, 'Message envoye, sans confirmation explicite du pair.')
        else:
            lines = (result.stderr or result.stdout or '').strip().splitlines()
            details = lines[-1] if lines else 'Erreur inconnue'
            flash_status(False, f'Envoi echoue: {details}')
        return redirect(url_for('chat'))
    if not ensure_node_running(default_port):
        start_node_process(default_port)
        flash_status(True, f'Listener chat auto lance sur {default_port}.')
    return render_template('chat.html', local_port=default_port)


@app.route('/chat/messages', methods=['GET'])
def chat_messages():
    since = int(request.args.get('since', '0'))
    with MESSAGE_LOCK:
        items = [m for m in CHAT_MESSAGES if m['ts'] > since]
    return jsonify({'messages': items})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
