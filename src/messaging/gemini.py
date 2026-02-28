import json
import os
from urllib import error, request

from dotenv import load_dotenv

load_dotenv()
DEFAULT_MODEL = os.getenv('GEMINI_MODEL', 'gemini-2.0-flash')


def _http_json(url: str, payload: dict | None = None, timeout: int = 30) -> dict:
    body = json.dumps(payload).encode('utf-8') if payload is not None else None
    req = request.Request(
        url,
        data=body,
        headers={'Content-Type': 'application/json'},
        method='POST' if payload is not None else 'GET',
    )
    with request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8'))


def _pick_model(api_key: str, timeout: int) -> str:
    url = f'https://generativelanguage.googleapis.com/v1beta/models?key={api_key}'
    data = _http_json(url, timeout=timeout)
    models = data.get('models') or []

    candidates = []
    for m in models:
        name = m.get('name', '')
        methods = m.get('supportedGenerationMethods') or []
        if 'generateContent' in methods:
            short_name = name.split('/', 1)[-1]
            candidates.append(short_name)

    for preferred in ('gemini-2.0-flash', 'gemini-2.5-flash', 'gemini-1.5-flash'):
        if preferred in candidates:
            return preferred
    if candidates:
        return candidates[0]
    raise RuntimeError('Aucun modele Gemini compatible generateContent.')


def ask_gemini(prompt: str, api_key: str | None = None, model: str = DEFAULT_MODEL, timeout: int = 30) -> str:
    text = (prompt or '').strip()
    if not text:
        raise ValueError('Prompt vide.')

    key = (api_key or os.getenv('GEMINI_API_KEY', '')).strip()
    if not key or key == 'your_key_here':
        raise RuntimeError('GEMINI_API_KEY absente. Configure .env.')

    resolved_model = model
    url = f'https://generativelanguage.googleapis.com/v1beta/models/{resolved_model}:generateContent?key={key}'
    payload = {
        'contents': [
            {
                'parts': [
                    {'text': text},
                ]
            }
        ]
    }
    body = json.dumps(payload).encode('utf-8')
    req = request.Request(
        url,
        data=body,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )

    try:
        with request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode('utf-8')
    except error.HTTPError as exc:
        detail = exc.read().decode('utf-8', errors='ignore')
        if exc.code == 404:
            resolved_model = _pick_model(key, timeout=timeout)
            retry_url = f'https://generativelanguage.googleapis.com/v1beta/models/{resolved_model}:generateContent?key={key}'
            retry_req = request.Request(
                retry_url,
                data=body,
                headers={'Content-Type': 'application/json'},
                method='POST',
            )
            with request.urlopen(retry_req, timeout=timeout) as resp:
                raw = resp.read().decode('utf-8')
        else:
            raise RuntimeError(f'Gemini HTTP {exc.code}: {detail[:180]}') from exc
    except error.URLError as exc:
        raise RuntimeError(f'Reseau Gemini indisponible: {exc.reason}') from exc

    data = json.loads(raw)
    candidates = data.get('candidates') or []
    if not candidates:
        raise RuntimeError('Reponse Gemini vide.')

    parts = candidates[0].get('content', {}).get('parts', [])
    texts = [p.get('text', '').strip() for p in parts if p.get('text')]
    if not texts:
        raise RuntimeError('Gemini n a pas retourne de texte.')
    return '\n'.join(texts).strip()
