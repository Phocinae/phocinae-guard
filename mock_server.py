#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mock_server.py —— phocinae-guard 测试用本地 mock（纯标准库）。

POST /v1/systemone 返回固定 noul/score（可按命令正则规则区分）。
仅用于本地测试（任务书要求），绝不对外提供服务。

用法：
  python3 mock_server.py [--host 127.0.0.1] [--port 8155]
                         [--noul 0.9] [--score 1.0] [--rules mock_rules.json]
规则文件：JSON 数组 [{"pattern": 正则, "noul": 0.5, "score": 5.0, "note": "..."}]
按顺序第一个 pattern 命中（对 state.command 全文 re.search）即用其 noul/score；
未命中 → 默认 noul/score。

也可被测试程序 import：make_server(...) 返回 HTTP 服务器对象。
"""
import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = "phocinae-mock-0"


def pick(command, rules, default_noul, default_score):
    for rule in rules:
        try:
            if re.search(rule.get("pattern", ""), command):
                return float(rule["noul"]), float(rule["score"])
        except re.error:
            continue
    return float(default_noul), float(default_score)

def handler_class(rules, default_noul, default_score):
    class _Handler(BaseHTTPRequestHandler):
        def _send_json(self, code, obj):
            raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path == "/health":
                self._send_json(200, {"status": "ok", "model": MODEL})
            else:
                self._send_json(404, {"error": "not found"})

        def do_POST(self):
            if self.path not in ("/v1/systemone", "/v1/systemone/"):
                self._send_json(404, {"error": "not found"})
                return
            length = int(self.headers.get("Content-Length", "0") or 0)
            try:
                req = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
            except ValueError:
                self._send_json(400, {"error": "bad json"})
                return
            command = ""
            state = req.get("state")
            if isinstance(state, dict):
                command = str(state.get("command", ""))
            elif isinstance(state, str):
                try:
                    state_obj = json.loads(state)
                    if isinstance(state_obj, dict):
                        command = str(state_obj.get("command", ""))
                except (ValueError, TypeError):
                    for line in state.splitlines():
                        if line.startswith("command: "):
                            command = line[len("command: "):]
                            break
            noul, score = pick(command, rules, default_noul, default_score)
            self._send_json(200, {
                "model": MODEL,
                "answers": {
                    "guard_noul": {"type": "noul", "noul": round(noul, 4)},
                    "guard_score": {
                        "type": "score",
                        "score": round(score, 4),
                        "legend": {str(i): str(i) for i in range(11)},
                        "probabilities": {"0": 1.0},
                        "confidence": 0.9,
                    },
                },
                "usage": {"input_tokens": 0, "output_tokens": 0},
            })

        def log_message(self, fmt, *args):
            return  # 测试静默

    return _Handler


def make_server(host="127.0.0.1", port=0, rules=None,
                default_noul=0.9, default_score=1.0):
    return ThreadingHTTPServer((host, port),
                               handler_class(rules or [], default_noul,
                                             default_score))


def main():
    ap = argparse.ArgumentParser(description="phocinae-guard 测试用 mock")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8155)
    ap.add_argument("--noul", type=float, default=0.9, help="默认 noul=P(放行)")
    ap.add_argument("--score", type=float, default=1.0, help="默认 score=风险 0-10")
    ap.add_argument("--rules", default="", help="规则 JSON 文件（按命令正则区分）")
    args = ap.parse_args()
    rules = []
    if args.rules:
        with open(args.rules, "r", encoding="utf-8") as fh:
            rules = json.load(fh)
    srv = make_server(args.host, args.port, rules=rules,
                      default_noul=args.noul, default_score=args.score)
    print("mock_server listening on %s:%d (default noul=%s score=%s, %d rules)"
          % (args.host, srv.server_address[1], args.noul, args.score,
             len(rules)), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
