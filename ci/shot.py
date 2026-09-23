"""CI-only: render the signer UI with fake data (no token) and save screenshots."""
import base64, ctypes, ctypes.wintypes as wt, datetime, http.client, json, os, sys, tempfile, threading
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "broto_signer"))
os.environ["APPDATA"] = tempfile.mkdtemp()          # never touch the runner's real settings
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
CERT = CertInfo(label="", subject="", common_name="HARSHIT JAIN",
                issuer="e-Mudhra Sub CA for Class 3 Individual 2022",
                not_after=datetime.datetime(2027, 3, 14, tzinfo=datetime.timezone.utc))
if stage not in ("empty",):
    a.pin_entry.insert(0, "12345678")
    a.q.put(("certs", [CERT]))
if stage in ("ready", "done"):
    a._add([os.path.join(demo, f) for f in sorted(os.listdir(demo))])
if stage == "done":
    for i, r in enumerate(a.rows):
        if i == 2:
            a.q.put(("file", i, "fail", "Not a valid ICEGATE flat file (no header record)"))
        else:
            b, e = os.path.splitext(os.path.basename(r.path))
            a.q.put(("file", i, "ok", b + "Signed" + e))
    a.q.put(("done", 3, 1, demo, "12345678"))
if stage == "log":
    a._log("Token driver: C:\\Windows\\System32\\SignatureP11.dll")
    root.after(800, a._open_log)
BE = {"headerField": {"senderID": "SUNWAYCHA", "receiverID": "INNSA1", "indicator": "P", "messageID": "CACHI01",
                      "sequenceOrControlNumber": 1, "jobNumber": 4382026, "jobDate": "20260922", "messageType": "F"},
      "master": {"beModel": [{"iecCode": "0512345678", "nameOfImporter": "ACME IMPORTS PRIVATE LIMITED"}],
                 "invoiceModel": [{}, {}], "itemsModel": [{}] * 14}}
result = {}
def post():
    c = http.client.HTTPConnection("127.0.0.1", 47811, timeout=60)
    body = json.dumps({"filename": "4382026.json", "action": "sign_and_file",
                       "content_b64": base64.b64encode(json.dumps(BE).encode()).decode()})
    c.request("POST", "/sign", body=body, headers={"Origin": "https://brotoai.com", "Content-Type": "application/json"})
    r = c.getresponse(); result["status"] = r.status; result["body"] = r.read().decode()
if stage == "approve":
    root.after(1200, lambda: threading.Thread(target=post, daemon=True).start())
if stage == "savepin":
    root.after(1200, lambda: setattr(a, "_savepin", A.SavePinDialog(a, "12345678")))
def snap():
    target = root
    if stage == "log" and a._log_win is not None: target = a._log_win
    if stage == "approve" and a._approval is not None: target = a._approval
    if stage == "savepin" and getattr(a, "_savepin", None) is not None: target = a._savepin
    target.update()
    rect = wt.RECT()
    ctypes.windll.user32.GetWindowRect(int(target.wm_frame(), 16), ctypes.byref(rect))
    ImageGrab.grab(bbox=(rect.left, rect.top, rect.right, rect.bottom), all_screens=True).save(out)
    if stage == "approve":
        assert a.bridge_ok, "bridge did not start"
        assert a._approval is not None, "approval popup did not open"
        a._approval.cancel()          # decline → the HTTP call must come back 'cancelled'
        root.after(1500, finish)
    else:
        root.destroy()
def finish():
    print("bridge response:", result)
    assert result.get("status") == 200 and '"cancelled"' in result.get("body", ""), result
    root.destroy()
root.after(3500, snap); root.attributes("-topmost", True)
root.mainloop()
