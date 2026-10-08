"""Network-free regressions for actual panel helpers and export methods."""
from contextlib import contextmanager
import hashlib
import importlib
import io
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch
import wave

from allint52 import PANELS, _support
from allint52 import audint, geomint, imgmint, osint, socmint, vedmint, webint
from allint52.__main__ import main


class PanelTests(unittest.TestCase):
    def test_all_panels_import_without_display(self):
        for module, cls in PANELS.values():
            self.assertTrue(hasattr(importlib.import_module('allint52.' + module), cls))

    def test_no_default_authorization_in_any_panel(self):
        for module, cls in PANELS.values():
            fields = {}
            sink = types.SimpleNamespace(set_widget_value=lambda key, value: fields.__setitem__(key, value))
            getattr(importlib.import_module('allint52.' + module), cls)._set_defaults(sink)
            authorization = json.loads(fields['authorization'])
            self.assertEqual(authorization['authorization_basis'], '')
            self.assertEqual(authorization['authorized_by'], '')
            self.assertFalse(_support.has_authorization(authorization))

    def test_missing_connector_description_is_not_configuration(self):
        self.assertFalse(_support.has_configuration(['None configured. Planning only.']))
        self.assertFalse(_support.has_configuration([]))
        self.assertFalse(_support.has_authorization({'authorization_basis': None}))
        self.assertFalse(_support.has_authorization({'authorization_basis': []}))

    def test_six_real_export_methods_reject_changed_payload(self):
        for module, cls in PANELS.values():
            if module == 'osint':
                continue
            m = importlib.import_module('allint52.' + module)
            obj = types.SimpleNamespace(last_result={'payload': {'case_id': 'old'}},
                                        collect_payload=lambda: {'case_id': 'new'})
            with patch.object(m.filedialog, 'asksaveasfilename') as dialog, patch.object(m.messagebox, 'showwarning') as warning:
                getattr(m, cls).export_json(obj)
            dialog.assert_not_called()
            warning.assert_called_once()

    def test_current_export_ignores_generated_timestamp(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / 'result.json'
            obj = types.SimpleNamespace(last_result={'payload': {'case_id': 'same', 'generated_at': 'earlier'}, 'local_evidence': ['synthetic']},
                                        collect_payload=lambda: {'case_id': 'same', 'generated_at': 'later'})
            with patch.object(socmint.filedialog, 'asksaveasfilename', return_value=str(target)), patch.object(socmint.messagebox, 'showinfo'):
                socmint.TraceAtlasSOCMINTPanel.export_json(obj)
            self.assertEqual(json.loads(target.read_text())['local_evidence'], ['synthetic'])

    def test_export_without_cached_result_generates_current_plan(self):
        with tempfile.TemporaryDirectory() as td:
            obj = types.SimpleNamespace(last_result={}, collect_payload=lambda: {'case_id': 'current'})
            obj.generate_plan = lambda: setattr(obj, 'last_result', {'payload': obj.collect_payload()})
            target = Path(td) / 'result.json'
            with patch.object(socmint.filedialog, 'asksaveasfilename', return_value=str(target)), patch.object(socmint.messagebox, 'showinfo'):
                socmint.TraceAtlasSOCMINTPanel.export_json(obj)
            self.assertEqual(json.loads(target.read_text())['payload']['case_id'], 'current')

    def test_policy_preview_cannot_export_as_complete_snapshot(self):
        obj = types.SimpleNamespace(last_result={'payload_preview': {'case_id': 'x'}}, collect_payload=lambda: {'case_id': 'x'})
        with patch.object(socmint.filedialog, 'asksaveasfilename') as dialog, patch.object(socmint.messagebox, 'showwarning'):
            socmint.TraceAtlasSOCMINTPanel.export_json(obj)
        dialog.assert_not_called()

    def test_old_analysis_cannot_follow_new_case(self):
        obj = types.SimpleNamespace(_analysis_payload={'case_id': 'old'}, analyzed_images=[1], analyzed_audio=[2], analyzed_videos=[3], extracted_segments=[4], extracted_frames=[5])
        _support.invalidate_analysis(obj, {'case_id': 'new'})
        self.assertEqual(obj.analyzed_audio, [])
        self.assertEqual(obj.analyzed_images, [])
        self.assertEqual(obj.analyzed_videos, [])
        self.assertEqual(obj.extracted_frames, [])
        self.assertEqual(obj.extracted_segments, [])

    def test_same_input_analysis_is_retained(self):
        obj = types.SimpleNamespace(_analysis_payload={'case_id': 'same', 'generated_at': 'a'}, analyzed_audio=[1])
        _support.invalidate_analysis(obj, {'case_id': 'same', 'generated_at': 'b'})
        self.assertEqual(obj.analyzed_audio, [1])

    def test_osint_plan_has_budget_and_unverified_rows(self):
        cls = osint.TraceAtlasOSINTPanel
        methods = {name: getattr(cls, name) for name in ('_default_questions', '_query_families_for_target', '_compile_query', '_estimate_information_value', '_estimate_cost')}
        obj = types.SimpleNamespace()
        for name, fn in methods.items():
            setattr(obj, name, types.MethodType(fn, obj))
        plan = cls._build_search_plan(obj, {'target': 'example.com', 'target_type': 'domain', 'questions': ['What domains?'] * 1000})
        self.assertLessEqual(len(plan), 250)
        self.assertEqual(len(plan), 250)
        self.assertTrue(all(row['authorization_status'] == 'NOT_VERIFIED_PLANNING_ONLY' for row in plan))

    def test_launcher_lists_only_implemented_panels(self):
        with patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(main(['--list']), 0)
        self.assertIn('46 empty domain placeholders', out.getvalue())
        self.assertNotIn('procurementint: ', out.getvalue())

    def test_safe_export_filename(self):
        self.assertNotIn('/', _support.safe_filename('../../case/private'))
        self.assertNotIn('\\', _support.safe_filename('case\\private'))


class URLTests(unittest.TestCase):
    def test_actual_http_parser_fetch_and_redaction_without_network(self):
        body = b'{"password":"fixture-value","title":"public"}'
        raw = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body
        class FakeSocket:
            def settimeout(self, timeout):
                pass
            def connect(self, address):
                self.address = address
            def sendall(self, data):
                pass
            def makefile(self, mode):
                return io.BytesIO(raw)
            def close(self):
                pass
        sock = FakeSocket()
        with patch.object(_support.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('1.1.1.1', 80))]), patch.object(_support.socket, 'socket', return_value=sock):
            result = webint.safe_fetch_url('http://example.com/', ['example.com'])
        self.assertEqual(result['status'], 'SUCCEEDED')
        self.assertEqual(result['content_hash'], hashlib.sha256(body).hexdigest())
        self.assertNotIn('fixture-value', json.dumps(result))
        self.assertEqual(sock.address, ('1.1.1.1', 80))

    def test_rebinding_at_transport_rejected_by_real_fetch(self):
        public = [(2, 1, 6, '', ('1.1.1.1', 80))]
        private = [(2, 1, 6, '', ('127.0.0.1', 80))]
        with patch.object(_support.socket, 'getaddrinfo', side_effect=[public, public, private]), patch.object(_support.socket, 'socket') as connect:
            result = webint.safe_fetch_url('http://example.com/', ['example.com'])
        self.assertEqual(result['status'], 'FAILED_EXCEPTION')
        connect.assert_not_called()

    def test_malformed_port_is_structured_failure(self):
        self.assertFalse(webint.validate_public_url('https://example.com:bad/')[0])
        self.assertEqual(webint.safe_fetch_url('https://example.com:bad/')['status'], 'BLOCKED_POLICY')

    def test_ipv6_brackets_preserved(self):
        ok, normalized, _ = webint.validate_public_url('https://[2606:4700:4700::1111]/')
        self.assertTrue(ok)
        self.assertEqual(normalized, 'https://[2606:4700:4700::1111]/')

    def test_nonpublic_hosts_rejected(self):
        for url in ['http://127.0.0.1/', 'http://169.254.169.254/', 'http://100.64.0.1/', 'file:///tmp/x']:
            self.assertFalse(webint.validate_public_url(url)[0])

    def test_mismatched_scheme_port_rejected(self):
        self.assertFalse(webint.validate_public_url('https://1.1.1.1:80/')[0])
        self.assertFalse(webint.validate_public_url('http://1.1.1.1:443/')[0])

    def test_allowed_domain_requires_dns_public_address(self):
        with patch.object(webint.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('1.1.1.1', 80))]):
            self.assertTrue(webint.validate_public_url('https://example.com/', ['example.com'])[0])
            self.assertFalse(webint.validate_public_url('https://other.example/', ['example.com'])[0])

    def test_connect_is_pinned_to_single_validated_resolution(self):
        sock = MagicMock()
        conn = MagicMock()
        conn.getresponse.return_value.status = 200
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.1.1.1', 80))]
        with patch.object(_support.socket, 'getaddrinfo', side_effect=[answers, [(2, 1, 6, '', ('127.0.0.1', 80))]]) as resolve, patch.object(_support.socket, 'socket', return_value=sock), patch.object(_support.http.client, 'HTTPConnection', return_value=conn):
            with _support.open_public_url('http://example.com/page', {}) as response:
                self.assertEqual(response.status, 200)
        self.assertEqual(resolve.call_count, 1)
        sock.connect.assert_called_once_with(('1.1.1.1', 80))
        conn.request.assert_called_once_with('GET', '/page', headers={})
        conn.close.assert_called_once()

    def test_tls_uses_original_hostname_and_verified_context(self):
        sock = MagicMock()
        context = MagicMock()
        conn = MagicMock()
        conn.getresponse.return_value.status = 200
        with patch.object(_support.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('1.1.1.1', 443))]), patch.object(_support.socket, 'socket', return_value=sock), patch.object(_support.ssl, 'create_default_context', return_value=context) as verified, patch.object(_support.http.client, 'HTTPConnection', return_value=conn):
            with _support.open_public_url('https://example.com/', {}):
                pass
        verified.assert_called_once()
        context.wrap_socket.assert_called_once_with(sock, server_hostname='example.com')

    def test_mixed_private_dns_answers_never_connect(self):
        answers = [(2, 1, 6, '', ('1.1.1.1', 80)), (2, 1, 6, '', ('127.0.0.1', 80))]
        with patch.object(_support.socket, 'getaddrinfo', return_value=answers), patch.object(_support.socket, 'socket') as connect:
            with self.assertRaises(ValueError):
                with _support.open_public_url('http://example.com/', {}):
                    pass
        connect.assert_not_called()

    def test_redirect_revalidates_target_before_fetch(self):
        from email.message import Message
        from urllib.error import HTTPError
        headers = Message()
        headers['Location'] = 'http://127.0.0.1/'
        with patch.object(webint, 'validate_public_url', side_effect=[(True, 'http://example.com/', []), (True, 'http://example.com/', []), (False, 'http://127.0.0.1/', ['SSRF_PRIVATE_OR_UNSAFE_HOST'])]), patch.object(_support, 'open_public_url', side_effect=HTTPError('http://example.com/', 302, 'Found', headers, None)) as fetch:
            result = webint.safe_fetch_url('http://example.com/')
        self.assertEqual(result['status'], 'BLOCKED_POLICY')
        self.assertEqual(fetch.call_count, 1)

    def test_json_and_html_sensitive_values_redacted(self):
        for text in [json.dumps({'outer': [{'password': 'fixture-value'}]}), '<input password="fixture-value">', "token='fixture-value'"]:
            self.assertNotIn('fixture-value', webint.redact_sensitive_text(text))


class MediaTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('ffmpeg') and shutil.which('ffprobe'), 'FFmpeg optional')
    def test_actual_video_probe_frames_and_original_integrity(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'video.mp4'
            subprocess.run([shutil.which('ffmpeg'), '-hide_banner', '-loglevel', 'error', '-f', 'lavfi', '-i', 'color=c=blue:s=16x16:d=1', '-c:v', 'mpeg4', str(p)], check=True, timeout=10, stdin=subprocess.DEVNULL)
            before = hashlib.sha256(p.read_bytes()).hexdigest()
            self.assertEqual(vedmint.analyze_video_file(str(p))['status'], 'SUCCEEDED')
            a = vedmint.extract_sample_frames_for_video(str(p), td, max_frames=1)
            b = vedmint.extract_sample_frames_for_video(str(p), td, max_frames=1)
            self.assertEqual(a[0]['status'], 'SUCCEEDED')
            self.assertEqual(b[0]['status'], 'SUCCEEDED')
            self.assertNotEqual(a[0]['output_path'], b[0]['output_path'])
            self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), before)

    def test_missing_inputs_are_structured(self):
        with tempfile.TemporaryDirectory() as td:
            p = str(Path(td) / 'missing')
            for fn in (imgmint.analyze_image_file, audint.analyze_audio_file, vedmint.analyze_video_file):
                self.assertEqual(fn(p)['status'], 'FAILED_FILE_NOT_FOUND')

    def test_size_budget_rejects_before_hash_or_decode(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'large.bin'
            p.write_bytes(b'1234')
            with patch.object(_support, 'MAX_MEDIA_BYTES', 3):
                for fn in (imgmint.analyze_image_file, audint.analyze_audio_file, vedmint.analyze_video_file):
                    self.assertEqual(fn(str(p))['status'], 'BLOCKED_FILE_LIMIT')

    @unittest.skipUnless(imgmint.PIL_AVAILABLE, 'Pillow optional')
    def test_image_pixel_budget_before_decode(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'image.png'
            imgmint.Image.new('RGB', (10, 10)).save(p)
            with patch.object(_support, 'MAX_IMAGE_PIXELS', 50):
                self.assertEqual(imgmint.analyze_image_file(str(p))['status'], 'BLOCKED_PIXEL_LIMIT')

    def test_extraction_limits(self):
        self.assertEqual(audint.extract_sample_segments_for_audio('/missing', '/missing', max_segments=4)[0]['status'], 'BLOCKED_EXTRACTION_LIMIT')
        self.assertEqual(vedmint.extract_sample_frames_for_video('/missing', '/missing', max_frames=4)[0]['status'], 'BLOCKED_EXTRACTION_LIMIT')

    def test_unique_derivatives_do_not_collide(self):
        self.assertNotEqual(_support.derived_path('/tmp', 'same', 'frame.jpg'), _support.derived_path('/tmp', 'same', 'frame.jpg'))

    def test_decoder_output_budget_and_timeout(self):
        with patch.object(_support, 'MAX_DECODER_OUTPUT', 100):
            with self.assertRaises(ValueError):
                _support.run_decoder([sys.executable, '-c', 'print("x" * 200)'], timeout=5)
        with self.assertRaises(subprocess.TimeoutExpired):
            _support.run_decoder([sys.executable, '-c', 'import time; time.sleep(1)'], timeout=0.05)

    @unittest.skipUnless(shutil.which('ffmpeg') and shutil.which('ffprobe'), 'FFmpeg optional')
    def test_actual_audio_probe_extract_and_original_integrity(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'audio.wav'
            with wave.open(str(p), 'wb') as stream:
                stream.setnchannels(1)
                stream.setsampwidth(2)
                stream.setframerate(16000)
                stream.writeframes(b'\0\0' * 16000)
            before = hashlib.sha256(p.read_bytes()).hexdigest()
            self.assertEqual(audint.analyze_audio_file(str(p))['status'], 'SUCCEEDED')
            a = audint.extract_sample_segments_for_audio(str(p), td, max_segments=1)
            b = audint.extract_sample_segments_for_audio(str(p), td, max_segments=1)
            self.assertEqual(a[0]['status'], 'SUCCEEDED')
            self.assertEqual(b[0]['status'], 'SUCCEEDED')
            self.assertNotEqual(a[0]['output_path'], b[0]['output_path'])
            self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), before)


if __name__ == '__main__':
    unittest.main()
