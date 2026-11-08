import importlib.util, pathlib, unittest

spec = importlib.util.spec_from_file_location("mm", pathlib.Path(__file__).with_name("mirror-manifest.py"))
mm = importlib.util.module_from_spec(spec); spec.loader.exec_module(mm)

GH = "https://github.com/o/r/releases/download/v0.2.0"
M = {"version": "0.2.0", "notes": "n", "pub_date": "2026-10-22T00:00:00Z", "platforms": {
    "linux-x86_64": {"signature": "SIG-L", "url": f"{GH}/Eleutheria_0.2.0_amd64.AppImage"},
    "windows-x86_64": {"signature": "SIG-W", "url": f"{GH}/Eleutheria_0.2.0_x64-setup.exe"},
    "darwin-aarch64": {"signature": "SIG-M", "url": f"{GH}/Eleutheria_aarch64.app.tar.gz"},
    "darwin-aarch64-app": {"signature": "SIG-M", "url": f"{GH}/Eleutheria_aarch64.app.tar.gz"}}}
BASE = "https://updates.example.org/eleutheria/v0.2.0"

class T(unittest.TestCase):
    def test_urls_move_signatures_and_version_stay(self):
        out, files = mm.rewrite(M, BASE + "/")
        self.assertEqual(out["platforms"]["linux-x86_64"]["url"], f"{BASE}/Eleutheria_0.2.0_amd64.AppImage")
        for k, p in out["platforms"].items():
            self.assertEqual(p["signature"], M["platforms"][k]["signature"], k)
            self.assertTrue(p["url"].startswith(BASE + "/"), k)
        self.assertEqual((out["version"], out["notes"], out["pub_date"]), ("0.2.0", "n", "2026-10-22T00:00:00Z"))
        self.assertEqual(len(files), 3, "общий файл выкладывается один раз")
        self.assertIn(GH, M["platforms"]["linux-x86_64"]["url"], "исходный манифест не изменён")

    def test_rejects_bad_input(self):
        bad = lambda f: self.assertRaises(ValueError, f)
        bad(lambda: mm.rewrite(M, "http://insecure.example/x"))
        bad(lambda: mm.rewrite({"platforms": {}}, BASE))
        bad(lambda: mm.rewrite({}, BASE))
        bad(lambda: mm.rewrite({"platforms": {"a": {"signature": "", "url": GH + "/x"}}}, BASE))
        bad(lambda: mm.rewrite({"platforms": {"a": {"signature": "s", "url": "http://h/x"}}}, BASE))
        bad(lambda: mm.rewrite({"platforms": {"a": {"signature": "s", "url": "https://h/"}}}, BASE))

    def test_filename_is_url_quoted(self):
        out, _ = mm.rewrite({"platforms": {"a": {"signature": "s", "url": "https://h/p/My%20App 1.exe"}}}, BASE)
        self.assertNotIn(" ", out["platforms"]["a"]["url"])

if __name__ == "__main__":
    unittest.main()
