import unittest

from app.parser import parse_url
from app.scorer import analyze


class TestParser(unittest.TestCase):
    def test_vn_domain(self):
        u = parse_url("https://ebank.vietcombank.com.vn/login")
        self.assertEqual(u.registered_domain, "vietcombank.com.vn")
        self.assertEqual(u.domain_name, "vietcombank")
        self.assertEqual(u.subdomain, "ebank")

    def test_missing_scheme(self):
        self.assertEqual(parse_url("shopee.vn").hostname, "shopee.vn")


class TestSafeLinks(unittest.TestCase):
    def test_official_sites_are_low_risk(self):
        for link in ["https://vietcombank.com.vn", "https://shopee.vn/sale",
                     "https://www.facebook.com/groups/abc", "https://hust.edu.vn"]:
            with self.subTest(link=link):
                self.assertLess(analyze(link)["score"], 30)


class TestPhishingLinks(unittest.TestCase):
    def test_brand_in_fake_domain(self):
        r = analyze("http://vietcombank-xacthuc.com/dang-nhap")
        self.assertGreaterEqual(r["score"], 60)
        self.assertEqual(r["level"], "dangerous")

    def test_typosquatting(self):
        self.assertGreaterEqual(analyze("https://vietcornbank.com")["score"], 40)
        self.assertGreaterEqual(analyze("https://sh0pee.vn")["score"], 40)

    def test_brand_in_subdomain(self):
        self.assertGreaterEqual(analyze("https://momo.vn.nhanqua.xyz")["score"], 60)

    def test_ip_and_at_symbol(self):
        self.assertGreaterEqual(analyze("http://192.168.1.10/login")["score"], 30)
        self.assertGreaterEqual(analyze("https://vietcombank.com.vn@evil.com")["score"], 30)

    def test_reasons_are_given(self):
        self.assertTrue(analyze("http://sh0pee-nhanqua.top")["reasons"])


class TestInvalidInput(unittest.TestCase):
    def test_no_hostname(self):
        for link in ["", " ", "http://"]:
            with self.subTest(link=link):
                self.assertIn("error", analyze(link))


class TestFalsePositives(unittest.TestCase):
    def test_short_brand_inside_word(self):
        for link in ["https://zalora.com", "https://tikitaka.com", "https://bidvietnam.com"]:
            with self.subTest(link=link):
                self.assertLess(analyze(link)["score"], 30)

    def test_short_brand_as_token_still_caught(self):
        for link in ["https://zalo-nhanqua.com", "https://tiki-hoantien.net",
                     "https://bidv.secure-login.top"]:
            with self.subTest(link=link):
                self.assertGreaterEqual(analyze(link)["score"], 40)


if __name__ == "__main__":
    unittest.main()
