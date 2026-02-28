import re
import subprocess
import sys
import threading
import time
from pathlib import Path

from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.messaging.gemini import ask_gemini

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'archipel-web-secret'

load_dotenv(PROJECT_ROOT / '.env')
RUNNING_NODES: dict[int, subprocess.Popen] = {}
MESSAGE_LOCK = threading.Lock()
CHAT_MESSAGES: list[dict] = []
MAX_CHAT_MESSAGES = 200
PORT_EVENT_LOCK = threading.Lock()
PORT_EVENTS: list[dict] = []
MAX_PORT_EVENTS = 500

CHAT_RECV_RE = re.compile(r'^\[(?:UDP-)?CHAT\]\s+recv\s+(.+?)\s+\|\s+(.+?)\s+says:\s+(.*)$')
MANIFEST_RE = re.compile(r'^\[SEND\]\s+manifest:\s+(.+)$', re.IGNORECASE)
AI_TRIGGER_TAG = '@archipel-ai'
AI_TRIGGER_CMD = '/ask'
AI_CONTEXT_SIZE = 12


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


def add_port_event(level: str, source: str, message: str, port: int | None = None) -> None:
    item = {
        'ts': int(time.time() * 1000),
        'level': level,
        'source': source,
        'port': port,
        'message': message,
    }
    with PORT_EVENT_LOCK:
        PORT_EVENTS.append(item)
        if len(PORT_EVENTS) > MAX_PORT_EVENTS:
            del PORT_EVENTS[: len(PORT_EVENTS) - MAX_PORT_EVENTS]


def get_running_ports() -> list[dict]:
    rows: list[dict] = []
    for port, proc in sorted(RUNNING_NODES.items()):
        rows.append(
            {
                'port': port,
                'pid': proc.pid,
                'running': proc.poll() is None,
            }
        )
    return rows


def _node_output_reader(port: int, proc: subprocess.Popen) -> None:
    if not proc.stdout:
        return
    for raw_line in proc.stdout:
        line = raw_line.strip()
        if line:
            add_port_event('info', 'node', line, port=port)
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
    add_port_event('info', 'web', f'Node launch requested (pid={proc.pid}).', port=port_local)
    threading.Thread(target=_node_output_reader, args=(port_local, proc), daemon=True).start()
    return proc


def ensure_node_running(port_local: int) -> bool:
    existing = RUNNING_NODES.get(port_local)
    return bool(existing and existing.poll() is None)


def extract_manifest_path(output: str) -> str | None:
    for line in output.splitlines():
        m = MANIFEST_RE.match(line.strip())
        if m:
            return m.group(1).strip()
    return None


def _is_ai_triggered(text: str) -> bool:
    value = (text or '').strip().lower()
    return value.startswith(AI_TRIGGER_CMD) or AI_TRIGGER_TAG in value


def _extract_ai_query(text: str) -> str:
    value = (text or '').strip()
    lower = value.lower()
    if lower.startswith(AI_TRIGGER_CMD):
        return value[len(AI_TRIGGER_CMD) :].strip()
    idx = lower.find(AI_TRIGGER_TAG)
    if idx >= 0:
        before = value[:idx].strip()
        after = value[idx + len(AI_TRIGGER_TAG) :].strip()
        return f'{before} {after}'.strip()
    return value


def _build_ai_context(limit: int = AI_CONTEXT_SIZE) -> str:
    with MESSAGE_LOCK:
        recent = CHAT_MESSAGES[-limit:]
    labels = {
        'out': 'Moi',
        'in': 'Pair',
        'ai_user': 'Moi->IA',
        'ai': 'Archipel-AI',
        'system': 'Systeme',
    }
    lines = []
    for item in recent:
        role = labels.get(item.get('direction', ''), 'Message')
        lines.append(f"{role}: {item.get('text', '')}")
    return '\n'.join(lines)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/terminal')
def terminal():
    return render_template('terminal.html', ports=get_running_ports())


@app.route('/terminal/events', methods=['GET'])
def terminal_events():
    since = int(request.args.get('since', '0'))
    with PORT_EVENT_LOCK:
        items = [m for m in PORT_EVENTS if m['ts'] > since]
    return jsonify({'events': items, 'ports': get_running_ports()})


@app.route('/share', methods=['GET', 'POST'])
def share():
    if request.method == 'POST':
        filepath = request.form['filepath']
        port_local = int(request.form.get('port_local', '7902'))
        path = make_path(filepath)

        if not path.exists():
            add_port_event('error', 'share', f'File not found: {path}', port=port_local)
            flash_status(False, f'Le fichier {path} est introuvable.')
            return redirect(url_for('share'))

        try:
            prep = run_command(['send', str(path)], timeout=60)
        except subprocess.TimeoutExpired:
            add_port_event('error', 'share', 'Manifest generation timeout.', port=port_local)
            flash_status(False, 'Generation du manifeste timeout.')
            return redirect(url_for('share'))

        if prep.returncode != 0:
            lines = (prep.stderr or prep.stdout or '').strip().splitlines()
            details = lines[-1] if lines else 'Erreur inconnue'
            add_port_event('error', 'share', f'Manifest generation failed: {details}', port=port_local)
            flash_status(False, f'Impossible de generer le manifeste JSON: {details}')
            return redirect(url_for('share'))

        manifest_path = extract_manifest_path((prep.stdout or '') + '\n' + (prep.stderr or ''))
        if manifest_path and not Path(manifest_path).exists():
            add_port_event('error', 'share', f'Manifest path missing on disk: {manifest_path}', port=port_local)
            flash_status(False, f'Manifeste annonce mais introuvable: {manifest_path}')
            return redirect(url_for('share'))

        existing = RUNNING_NODES.get(port_local)
        if existing and existing.poll() is None:
            add_port_event('warn', 'share', f'Restarting node on port {port_local}.', port=port_local)
            existing.terminate()
            try:
                existing.wait(timeout=3)
            except subprocess.TimeoutExpired:
                existing.kill()

        proc = start_node_process(port_local, shared_file=path)
        RUNNING_NODES[port_local] = proc
        time.sleep(0.4)
        if proc.poll() is not None:
            add_port_event('error', 'share', 'Node failed to start (port busy or runtime error).', port=port_local)
            flash_status(False, f'Node non demarre sur {port_local} (port deja utilise ou erreur).')
            return redirect(url_for('share'))

        if manifest_path:
            add_port_event('info', 'share', f'Sharing active; manifest={manifest_path}', port=port_local)
            flash_status(
                True,
                f'Partage actif sur {port_local}. Manifeste JSON enregistre: {manifest_path}',
            )
        else:
            add_port_event('info', 'share', 'Sharing active; manifest generated in manifests/.', port=port_local)
            flash_status(True, f'Partage actif sur {port_local}. JSON cree dans manifests/.')
        return redirect(url_for('share'))
    return render_template('share.html')


@app.route('/stop-node', methods=['POST'])
def stop_node():
    port_local = int(request.form.get('port_local', '0'))
    proc = RUNNING_NODES.get(port_local)
    if not proc or proc.poll() is not None:
        add_port_event('warn', 'share', 'Stop requested but node is not running.', port=port_local)
        flash_status(False, f'Aucun node actif sur le port {port_local}.')
        return redirect(url_for('share'))
    proc.terminate()
    add_port_event('info', 'share', f'Node stopped (pid={proc.pid}).', port=port_local)
    flash_status(True, f'Node arrete sur le port {port_local}.')
    return redirect(url_for('share'))


@app.route('/download', methods=['GET', 'POST'])
def download():
    if request.method == 'POST':
        manifest = make_path(request.form['manifest'])
        port_local = int(request.form.get('port_local', '7903'))
        transport = request.form.get('transport', 'tcp')

        if not manifest.exists():
            add_port_event('error', 'download', f'Manifest not found: {manifest}', port=port_local)
            flash_status(False, f'Manifeste {manifest} introuvable.')
            return redirect(url_for('download'))

        add_port_event('info', 'download', f'Download requested via {transport}, manifest={manifest}.', port=port_local)
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
            add_port_event('error', 'download', 'Download timeout.', port=port_local)
            flash_status(False, 'Download timeout: relance avec un manifeste/peer valide.')
            return redirect(url_for('download'))

        if result.returncode == 0:
            add_port_event('info', 'download', 'Download completed successfully.', port=port_local)
            flash_status(True, 'Download termine. Verifie le dossier downloads/.')
        else:
            lines = (result.stderr or result.stdout or '').strip().splitlines()
            details = lines[-1] if lines else 'Erreur inconnue'
            add_port_event('error', 'download', f'Download failed: {details}', port=port_local)
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

        if _is_ai_triggered(message):
            query = _extract_ai_query(message)
            if not query:
                add_chat_message('system', "Archipel-AI: prompt vide. Utilise '/ask ta question'.")
                add_port_event('warn', 'chat', 'AI called with empty prompt.', port=port_local)
                flash_status(False, "Prompt vide pour l'assistant IA.")
                return redirect(url_for('chat'))

            context = _build_ai_context()
            add_chat_message('ai_user', query)
            add_port_event('info', 'chat', 'AI assistant prompt submitted.', port=port_local)
            full_prompt = (
                "Tu es Archipel-AI, assistant du projet P2P.\n"
                "Reponds en francais, de facon concise et actionnable.\n\n"
                f"Contexte recent du chat ({AI_CONTEXT_SIZE} messages max):\n{context}\n\n"
                f"Question utilisateur:\n{query}"
            )
            try:
                ai_reply = ask_gemini(full_prompt)
            except Exception as exc:
                add_chat_message('system', f'Archipel-AI indisponible: {exc}')
                add_port_event('error', 'chat', f'AI unavailable: {exc}', port=port_local)
                flash_status(False, 'Assistant IA indisponible (mode offline ou quota).')
                return redirect(url_for('chat'))
            add_chat_message('ai', ai_reply)
            add_port_event('info', 'chat', 'AI response generated.', port=port_local)
            flash_status(True, 'Reponse Archipel-AI generee.')
            return redirect(url_for('chat'))

        if not peer or not message:
            add_port_event('warn', 'chat', 'Message rejected: missing peer_id or message.', port=port_local)
            flash_status(False, 'Renseigne un peer ID et un message valides.')
            return redirect(url_for('chat'))

        if not ensure_node_running(port_local):
            proc = start_node_process(port_local)
            add_port_event('info', 'chat', f'Listener auto-started (pid={proc.pid}).', port=port_local)
            flash_status(True, f'Listener chat lance sur {port_local} (pid={proc.pid}).')

        cmd = ['msg', peer, message, '--port', str(port_local)]
        if peer_port:
            cmd.extend(['--peer-port', peer_port])
        if peer_ip:
            cmd.extend(['--peer-ip', peer_ip])

        add_port_event('info', 'chat', f'Message send requested to peer={peer}.', port=port_local)
        try:
            result = run_command(cmd, timeout=90)
        except subprocess.TimeoutExpired:
            add_port_event('error', 'chat', 'Message send timeout.', port=port_local)
            flash_status(False, 'Envoi message timeout.')
            return redirect(url_for('chat'))

        if result.returncode == 0:
            stdout = result.stdout or ''
            delivered = 'ack=OK' in stdout
            add_chat_message('out', message, peer=peer, port=port_local)
            if delivered:
                add_port_event('info', 'chat', f'Message delivered with ACK from {peer}.', port=port_local)
                add_chat_message('in', f'ACK recu du pair pour: {message}', peer=peer, port=port_local)
                flash_status(True, 'Message envoye et recu par le pair (ack=OK).')
            else:
                add_port_event('warn', 'chat', f'Message sent without explicit ACK from {peer}.', port=port_local)
                flash_status(True, 'Message envoye, sans confirmation explicite du pair.')
        else:
            lines = (result.stderr or result.stdout or '').strip().splitlines()
            details = lines[-1] if lines else 'Erreur inconnue'
            add_port_event('error', 'chat', f'Message send failed: {details}', port=port_local)
            flash_status(False, f'Envoi echoue: {details}')
        return redirect(url_for('chat'))
    if not ensure_node_running(default_port):
        start_node_process(default_port)
        add_port_event('info', 'chat', f'Chat listener auto-started on {default_port}.', port=default_port)
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
