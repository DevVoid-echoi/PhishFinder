"""Extract phishing signals from a page's HTML (standard library only)."""
import re
import unicodedata
from html.parser import HTMLParser
from urllib.parse import urljoin

from app.lookalike import BRANDS, CONFUSABLES, SHORT_BRAND_LEN, is_official
from app.parser import parse_url

OTP_HINTS = ("otp", "one-time-code", "ma xac thuc", "mã xác thực", "verification code", "sms code")
CARD_HINTS = ("cc-number", "cc-csc", "cc-exp", "cvv", "cvc", "card number", "so the", "số thẻ",
              "ngay het han", "ngày hết hạn")
SKIP_TAGS = {"script", "style", "noscript", "template"}
# Vietnamese ID numbers: CCCD (chip ID card), the older CMND, the personal ID number, passports.
# Not "passport" or "identity" alone: account systems use those words for a plain user name.
ID_HINTS = ("cccd", "cmnd", "can cuoc", "căn cước", "chung minh", "chứng minh",
            "so dinh danh", "số định danh", "ho chieu", "hộ chiếu")
MAX_TEXT = 3000  # enough for the AI to understand the page, and caps its cost


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title, self.text, self.inputs, self.forms = "", [], [], []
        self._skip, self._in_title = 0, False

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag in SKIP_TAGS:
            self._skip += 1
        elif tag == "title":
            self._in_title = True
        elif tag == "input":
            hints = " ".join(a.get(k, "") for k in ("type", "name", "id", "placeholder", "autocomplete"))
            self.inputs.append((a.get("type", "").lower(), hints.lower()))
        elif tag == "form":
            self.forms.append(a.get("action", ""))

    def handle_endtag(self, tag):
        if tag in SKIP_TAGS and self._skip:
            self._skip -= 1
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._skip:
            return
        if self._in_title:
            self.title += data
        elif data.strip():
            self.text.append(data.strip())


def strip_accents(text: str) -> str:
    """Vietnamese pages write brands with diacritics ("Bảo hiểm xã hội"); brands.json stores them without."""
    decomposed = unicodedata.normalize("NFD", text.replace("đ", "d").replace("Đ", "D"))
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def brands_in(text: str) -> list:
    """Brands named in free text. Short names and aliases must be whole words (zalo, not zalora)."""
    words = re.findall(r"[a-z0-9]+", strip_accents(text).lower().translate(CONFUSABLES))
    joined = "".join(words)
    found = set()
    for brand, info in BRANDS.items():
        for name in {brand} | info["aliases"]:
            if (name in words) if len(name) <= SHORT_BRAND_LEN else (name in joined):
                found.add(brand)
    return sorted(found)


def extract(html: str, page_url: str) -> dict:
    c = _Collector()
    c.feed(html)
    c.close()
    page_domain = parse_url(page_url).registered_domain

    form_domains = set()
    for action in c.forms:
        domain = parse_url(urljoin(page_url, action)).registered_domain
        if domain and domain != page_domain:
            form_domains.add(domain)

    return {
        "title": c.title.strip()[:200],
        "text": " ".join(c.text)[:MAX_TEXT],
        "has_password": any(kind == "password" for kind, _ in c.inputs),
        "has_otp": any(h in hints for _, hints in c.inputs for h in OTP_HINTS),
        "has_card": any(h in hints for _, hints in c.inputs for h in CARD_HINTS),
        "has_id_number": any(h in hints for _, hints in c.inputs for h in ID_HINTS),
        "external_form_domains": sorted(form_domains),
        # Title only: real shops write "pay with MoMo or Vietcombank" in the body
        "brands_in_title": brands_in(c.title),
        "page_is_official": is_official(page_domain),
    }
