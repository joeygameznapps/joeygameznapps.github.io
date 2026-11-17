"""Writes a strict Content-Security-Policy <meta> into every page of the site.
Each page's script-src allows only /assets/js and the exact inline scripts on that page (by hash), so re-run this
after changing any inline <script>. Usage: python3 -I csp.py <site dir>"""
import base64, glob, hashlib, os, re, sys
root = sys.argv[1]
META = re.compile(r'<meta http-equiv="Content-Security-Policy"[^>]*>\s*')
for path in sorted(glob.glob(os.path.join(root, "**/*.html"), recursive=True)):
    s = open(path, encoding="utf-8").read()
    hashes = sorted({"'sha256-%s'" % base64.b64encode(hashlib.sha256(b.encode()).digest()).decode()
                     for b in re.findall(r"<script>(.*?)</script>", s, re.S)})
    policy = "; ".join([
        "default-src 'none'",
        "script-src " + " ".join(["'self'"] + hashes),
        "style-src 'self'",
        "style-src-attr 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self'",
        "manifest-src 'self'",
        "connect-src https://api.web3forms.com",
        "form-action 'self' https://api.web3forms.com",
        "base-uri 'none'",
        "object-src 'none'",
        "frame-src 'none'",
        "upgrade-insecure-requests",
    ])
    tag = f'<meta http-equiv="Content-Security-Policy" content="{policy}">'
    if META.search(s):
        new = META.sub(tag + "\n  ", s, count=1)
    else:
        m = re.search(r'<meta charset="[^"]*">\s*', s, re.I)
        if not m: print("SKIP (no charset meta):", path); continue
        new = s[:m.end()] + tag + "\n  " + s[m.end():]
    # The policy must come before any script or stylesheet it governs.
    assert new.index(tag) < min([i for i in (new.find("<script"), new.find("<link")) if i >= 0] or [len(new)]), path
    if new != s:
        open(path, "w", encoding="utf-8").write(new)
print("ok")
