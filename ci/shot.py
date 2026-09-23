"""CI-only: render the signer UI with fake data (no token) and save screenshots."""
import ctypes, datetime, os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "broto_signer"))
import customtkinter as ctk
from PIL import ImageGrab
import app as A
from signer_core import CertInfo

mode, stage, out = sys.argv[1], sys.argv[2], sys.argv[3]
ctk.set_appearance_mode(mode)
demo = tempfile.mkdtemp()
for f in ("4382026.json", "4462026.json", "SB_4382026.sb", "INV-2231.pdf"):
    open(os.path.join(demo, f), "w").write("{}")
root = A._Root(); a = A.SignerApp(root)
a.pin_var.trace_add("write", lambda *_: a._refresh())
if stage != "empty":
    a.pin_var.set("12345678")
    a.q.put(("certs", [CertInfo(label="", subject="", common_name="HARSHIT JAIN",
                                issuer="e-Mudhra Sub CA for Class 3 Individual 2022",
                                not_after=datetime.datetime(2027, 3, 14, tzinfo=datetime.timezone.utc))]))
    a._add([os.path.join(demo, f) for f in sorted(os.listdir(demo))])
if stage == "done":
    for i, r in enumerate(a.rows):
        if i == 2:
            a.q.put(("file", i, "fail", "Not a valid ICEGATE flat file (no header record)"))
        else:
            b, e = os.path.splitext(os.path.basename(r.path))
            a.q.put(("file", i, "ok", b + "Signed" + e))
    a.q.put(("done", 3, 1, demo))
def snap():
    root.update()
    import ctypes.wintypes as wt
    rect = wt.RECT()
    hwnd = int(root.wm_frame(), 16)
    ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(rect))
    ImageGrab.grab(bbox=(rect.left, rect.top, rect.right, rect.bottom), all_screens=True).save(out)
    root.destroy()
root.after(3000, snap); root.attributes("-topmost", True)
root.mainloop()
