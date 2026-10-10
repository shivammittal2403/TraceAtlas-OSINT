"""Small deterministic safety helpers for standalone desktop panels.

These do not grant investigation authority or register canonical employees.
"""
from contextlib import contextmanager
import http.client
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import time
import uuid
from urllib.error import HTTPError
from urllib.parse import urlsplit

MAX_MEDIA_BYTES = 256 * 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000
MAX_DECODER_OUTPUT = 2 * 1024 * 1024
SENSITIVE_KEY = re.compile(r"(?i)^(?:password|passwd|pwd|token|access_token|refresh_token|api[_-]?key|secret|authorization|cookie)$")


def redact_text(text):
    def plain(value):
        value = re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
                       '[REDACTED_PRIVATE_KEY]', value, flags=re.S | re.I)
        return re.sub(r'''(?ix)(["']?\b(?:password|passwd|pwd|token|access_token|refresh_token|api[_-]?key|secret)\b["']?\s*[:=]\s*)(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;<>]+)''',
                      r'\1"[REDACTED]"', value)

    def clean(value):
        if isinstance(value, dict):
            return {key: '[REDACTED]' if SENSITIVE_KEY.fullmatch(str(key)) else clean(val)
                    for key, val in value.items()}
        if isinstance(value, list):
            return [clean(val) for val in value]
        if isinstance(value, str):
            return redact_text(value)
        return value
    try:
        return json.dumps(clean(json.loads(text)), ensure_ascii=False)
    except (ValueError, TypeError):
        return plain(text)


def safe_filename(value):
    return re.sub(r'[^A-Za-z0-9_.-]', '_', str(value))[:100].strip('.') or 'record'


def input_payload(payload):
    return {key: value for key, value in payload.items() if key != 'generated_at'}


def has_configuration(value):
    return bool(value) and not any('none configured' in str(item).lower()
                                   for item in (value if isinstance(value, list) else [value]))


def has_authorization(value):
    if not isinstance(value, dict):
        return False
    basis = value.get('authorization_basis')
    return isinstance(basis, str) and bool(basis.strip())


def invalidate_analysis(panel, payload):
    prior = getattr(panel, '_analysis_payload', None)
    if prior is not None and input_payload(prior) != input_payload(payload):
        for name in ('analyzed_images', 'analyzed_audio', 'analyzed_videos',
                     'extracted_frames', 'extracted_segments'):
            if hasattr(panel, name):
                setattr(panel, name, [])
        panel._analysis_payload = None


def export_snapshot(panel, dialog, messages):
    """Refuse stale snapshots; preserve current local analysis instead of regenerating it."""
    current = panel.collect_payload()
    data = panel.last_result
    if data and input_payload(data.get('payload') or {}) != input_payload(current):
        messages.showwarning('Stale Output', 'Inputs changed or this result has no complete input snapshot. Generate a new plan or rerun analysis before exporting.')
        return
    if not data:
        panel.generate_plan()
        data = panel.last_result
    if not data or input_payload(data.get('payload') or {}) != input_payload(panel.collect_payload()):
        messages.showwarning('Missing Current Output', 'Generate a result for the current inputs before exporting.')
        return
    payload = data['payload']
    path = dialog.asksaveasfilename(defaultextension='.json',
        filetypes=[('JSON files', '*.json'), ('All files', '*.*')],
        initialfile=f"{safe_filename(payload.get('case_id', 'case'))}_{safe_filename(payload.get('task_id', 'task'))}.json")
    if not path:
        return
    try:
        with open(path, 'w', encoding='utf-8') as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
        messages.showinfo('Export Complete', f'JSON saved to:\n{path}')
    except (OSError, TypeError, ValueError) as exc:
        messages.showerror('Export Failed', str(exc))


def media_path(path):
    candidate = Path(path).expanduser().resolve(strict=True)
    if not candidate.is_file():
        raise ValueError('Media input must be a regular file')
    if candidate.stat().st_size > MAX_MEDIA_BYTES:
        raise ValueError('Media input exceeds 256 MiB limit')
    return candidate


def run_decoder(cmd, timeout):
    """Capture to temporary files instead of unbounded RAM; cap decoder verbosity."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        proc = subprocess.Popen(cmd, stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL)
        deadline = time.monotonic() + timeout
        try:
            while True:
                if max(stdout.tell(), stderr.tell()) > MAX_DECODER_OUTPUT:
                    raise ValueError('Decoder output exceeds 2 MiB limit')
                if proc.poll() is not None:
                    break
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(cmd, timeout)
                time.sleep(0.02)
            if max(stdout.tell(), stderr.tell()) > MAX_DECODER_OUTPUT:
                raise ValueError('Decoder output exceeds 2 MiB limit')
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
        stdout.seek(0)
        stderr.seek(0)
        return subprocess.CompletedProcess(cmd, proc.returncode,
            stdout.read(MAX_DECODER_OUTPUT).decode('utf-8', errors='replace'),
            stderr.read(MAX_DECODER_OUTPUT).decode('utf-8', errors='replace'))


def derived_path(outdir, stem, suffix):
    # Unique names plus ffmpeg -n prevent repeat runs or same-stem evidence from overwriting files.
    return Path(outdir) / f'{safe_filename(stem)}_{uuid.uuid4().hex}_{suffix}'


@contextmanager
def open_public_url(url, headers, timeout=10):
    """Resolve once, validate every answer, and connect to numeric addresses only.

    Preserve the original hostname for HTTP Host and TLS certificate validation.
    No environment proxies, cookies, redirect following or global DNS patching.
    """
    parsed = urlsplit(url)
    host = parsed.hostname
    if parsed.scheme not in ('http', 'https') or not host or parsed.username or parsed.password:
        raise ValueError('Public HTTP(S) URL required')
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    if port != (443 if parsed.scheme == 'https' else 80):
        raise ValueError('Only scheme-default ports are supported')
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses or len(addresses) > 16:
        raise ValueError('DNS address set missing or too large')
    if any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
        raise ValueError('DNS returned a non-public address')
    sock = None
    last_error = None
    for family, socktype, proto, _, address in addresses:
        candidate = socket.socket(family, socktype, proto)
        candidate.settimeout(timeout)
        try:
            candidate.connect(address)
            sock = candidate
            break
        except OSError as exc:
            last_error = exc
            candidate.close()
    if sock is None:
        raise last_error or OSError('Connection failed')
    connection = None
    try:
        if parsed.scheme == 'https':
            context = ssl.create_default_context()
            context.set_alpn_protocols(['http/1.1'])
            sock = context.wrap_socket(sock, server_hostname=host)
        connection = http.client.HTTPConnection(host, port, timeout=timeout)
        connection.sock = sock
        target = parsed.path or '/'
        if parsed.query:
            target += '?' + parsed.query
        connection.request('GET', target, headers=headers)
        response = connection.getresponse()
        if response.status >= 300:
            raise HTTPError(url, response.status, response.reason, response.headers, None)
        yield response
    finally:
        if connection is not None:
            connection.close()
        else:
            sock.close()
