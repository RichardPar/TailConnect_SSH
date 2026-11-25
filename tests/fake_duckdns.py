"""A fake DuckDNS /update endpoint that writes TXT records into pebble-challtestsrv."""
import http.server, json, sys, urllib.parse, urllib.request
MGMT = "http://127.0.0.1:8055"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if q.get("token") != ["test-token"]:
            body = b"KO"
        else:
            host = "_acme-challenge.%s.duckdns.org." % q["domains"][0]
            if q.get("clear") == ["true"]:
                req = urllib.request.Request(MGMT + "/clear-txt", json.dumps({"host": host}).encode())
            else:
                req = urllib.request.Request(MGMT + "/set-txt", json.dumps({"host": host, "value": q["txt"][0]}).encode())
            urllib.request.urlopen(req).read()
            body = b"OK\n127.0.0.1\n\nUPDATED"
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): sys.stderr.write("duckdns: %s\n" % (a[1] if len(a) > 1 else a))
http.server.HTTPServer(("127.0.0.1", 8099), H).serve_forever()
