"""Page-title decoding: GBK pages must not become U+FFFD (mojibake).

Observed on hniu.cn: mail.mail.hniu.cn, xs.hniu.cn and mail.xs.hniu.cn were
stored with title '������Ϣְҵ����ѧԺ' because httpx decodes a body as UTF-8
unless the response declares a charset, and those pages declare none. The
replacement characters were lossy -- the original bytes were gone by the time
the store saw them -- so the repair reads the raw body (-irrb) and decodes the
<title> with the page's own charset.

Everything here is offline: byte fixtures only.
"""
import base64

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from tests.util import fresh_core, fresh_tools

NAME = "湖南信息职业技术学院"
GBK = NAME.encode("gbk")
UTF8 = NAME.encode("utf-8")


def _page(title_bytes: bytes, charset: bytes | None = None) -> str:
    meta = (b'<meta charset="' + charset + b'">') if charset else b""
    html = (b"<html><head>" + meta + b"<title>" + title_bytes +
            b"</title></head><body>x</body></html>")
    return base64.b64encode(html).decode("ascii")


def _tools():
    return fresh_tools(fresh_core())


def test_gbk_page_title_decodes_correctly():
    """A GBK title with NO charset meta (the hniu.cn case) decodes to text."""
    tools = _tools()
    assert tools.title_from_body(_page(GBK)) == NAME


def test_declared_charset_is_honoured():
    """A page declaring gbk is decoded as gbk even if it looks like UTF-8."""
    tools = _tools()
    assert tools.title_from_body(_page(GBK, b"gbk")) == NAME


def test_utf8_page_title_is_unchanged():
    tools = _tools()
    assert tools.title_from_body(_page(UTF8)) == NAME


def test_ascii_title_is_unchanged():
    tools = _tools()
    assert tools.title_from_body(_page(b"Welcome to nginx!")) == "Welcome to nginx!"


def test_undecodable_title_is_not_considered_usable():
    """The U+FFFD marker is what triggers the raw-body re-read."""
    tools = _tools()
    assert tools._usable_title(NAME) is True
    assert tools._usable_title("������Ϣְҵ����ѧԺ") is False
    assert tools._usable_title("") is False
    assert tools._usable_title(None) is False


def test_missing_or_broken_body_yields_empty_title():
    tools = _tools()
    assert tools.title_from_body(None) == ""
    assert tools.title_from_body("") == ""
    assert tools.title_from_body("!!!not-base64!!!") == ""
    assert tools.title_from_body(base64.b64encode(b"<html>no title</html>").decode()) == ""


def test_tool_output_decoder_recovers_gbk_bytes():
    """A native tool answering in GBK must not be mangled by our reader."""
    from lib import core
    assert core.decode_tool_bytes(GBK) == NAME
    assert core.decode_tool_bytes(UTF8) == NAME
    d = core._LineDecoder()
    mid = len(GBK) // 2
    assert d.feed(GBK[:mid]) + d.feed(GBK[mid:]) == NAME
