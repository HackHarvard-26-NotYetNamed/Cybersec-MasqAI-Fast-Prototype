"""A minimal HTTP/1.1 client over one already-connected stream (a TLS socket on the device).

One request per connection (`Connection: close`), so no keep-alive state stays in RAM between calls (design §13.6).
Responses are capped: a body or header block larger than the cap raises RESP_TOO_LARGE instead of exhausting the heap.
Supports Content-Length, chunked, and read-to-close bodies.
"""


class HttpError(Exception):
    def __init__(self, code, msg=""):
        super().__init__(code + (": " + msg if msg else ""))
        self.code = code


MAX_HEAD = 4096


class _Reader:
    def __init__(self, stream, cap):
        self.stream = stream
        self.buf = b""
        self.cap = cap
        self.total = 0

    def _fill(self):
        chunk = self.stream.read(512)
        if not chunk:
            return False
        self.total += len(chunk)
        if self.total > self.cap + MAX_HEAD + 1024:
            raise HttpError("RESP_TOO_LARGE")
        self.buf += chunk
        return True

    def line(self, limit=MAX_HEAD):
        while b"\r\n" not in self.buf:
            if len(self.buf) > limit:
                raise HttpError("RESP_TOO_LARGE", "header line")
            if not self._fill():
                raise HttpError("BAD_RESPONSE", "connection closed in the headers")
        i = self.buf.index(b"\r\n")
        out, self.buf = self.buf[:i], self.buf[i + 2:]
        return out

    def exact(self, n):
        while len(self.buf) < n:
            if not self._fill():
                raise HttpError("BAD_RESPONSE", "connection closed in the body")
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def rest(self):
        while self._fill():
            if len(self.buf) > self.cap:
                raise HttpError("RESP_TOO_LARGE")
        out, self.buf = self.buf, b""
        return out


def build_request(method, host, path, bearer=None, body=None, user_agent="masqai-enigma-device"):
    lines = ["%s %s HTTP/1.1" % (method, path), "Host: " + host, "User-Agent: " + user_agent,
             "Accept: application/json", "Connection: close"]
    if bearer:
        lines.append("Authorization: Bearer " + bearer)
    if body is not None:
        lines.append("Content-Type: application/json")
        lines.append("Content-Length: %d" % len(body))
    elif method in ("POST", "PATCH", "PUT"):
        lines.append("Content-Length: 0")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode()
    return head + body if body is not None else head


def read_response(stream, cap=8192):
    """-> (status, headers {lowercase name: value}, body bytes)."""
    reader = _Reader(stream, cap)
    status_line = reader.line()
    parts = status_line.split(b" ", 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/1."):
        raise HttpError("BAD_RESPONSE", "status line")
    try:
        status = int(parts[1].decode())
    except (ValueError, UnicodeError):
        raise HttpError("BAD_RESPONSE", "status code")
    headers = {}
    size = 0
    while True:
        line = reader.line()
        if not line:
            break
        size += len(line)
        if size > MAX_HEAD * 2:
            raise HttpError("RESP_TOO_LARGE", "headers")
        cut = line.find(b":")
        if cut < 0:
            raise HttpError("BAD_RESPONSE", "header")
        headers[line[:cut].decode().strip().lower()] = line[cut + 1:].decode().strip()
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body = b""
        while True:
            size_line = reader.line(64).split(b";")[0].decode().strip()
            try:
                n = int(size_line, 16)
            except ValueError:
                raise HttpError("BAD_RESPONSE", "chunk size")
            if n == 0:
                break
            if len(body) + n > cap:
                raise HttpError("RESP_TOO_LARGE")
            body += reader.exact(n)
            reader.exact(2)
    elif "content-length" in headers:
        try:
            n = int(headers["content-length"])
        except ValueError:
            raise HttpError("BAD_RESPONSE", "content-length")
        if n < 0 or n > cap:
            raise HttpError("RESP_TOO_LARGE")
        body = reader.exact(n)
    else:
        body = reader.rest()
    return status, headers, body
