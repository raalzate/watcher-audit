from watcher.agent.procinfo import find_script, interpreter_of
from watcher.agent.sources.sessions import parse_teamviewer_line
from watcher.agent.sources.wineventlog import LSM, POWERSHELL, SYSMON, map_event, parse_events
from watcher.agent.spool import Spool
from watcher.common.chain import GENESIS, seal, verify
from watcher.common.redact import redact_args, redact_text


def test_chain_detects_modification():
    ev = seal({"event_id": "a", "seq": 1, "data": {"x": 1}}, GENESIS)
    assert verify(ev)
    ev["data"]["x"] = 2
    assert not verify(ev)


def test_redaction_of_arguments():
    args, n = redact_args(["mysql", "--password", "hunter2", "--user=bob", "--api-key=abc123", "-h", "db"])
    assert args == ["mysql", "--password", "***", "--user=bob", "--api-key=***", "-h", "db"]
    assert n == 2


def test_redaction_of_text():
    for secret, text in [
        ("s3cr3t", "curl https://bob:s3cr3t@example.com/x"),
        ("abcdefghijklmnop", "curl -H 'Authorization: Bearer abcdefghijklmnop' https://x"),
        ("AKIAIOSFODNN7EXAMPLE", "aws configure set key AKIAIOSFODNN7EXAMPLE"),
        ("P@ssw0rd!", "$p = ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force"),
        ("topsecret", "DB_PASSWORD=topsecret python app.py"),
        ("sk_live_9f8a7b6c5d4e3f2a1b0c", "cd x && python3 exportar.py out.csv --token sk_live_9f8a7b6c5d4e3f2a1b0c; sleep 3"),
        ("hunter2", "bash -c 'mysql --password hunter2 -h db'"),
        ("ghp_abcdefghijklmnopqrstuvwxyz0123", "git clone https://ghp_abcdefghijklmnopqrstuvwxyz0123@github.com/x/y"),
    ]:
        out, n = redact_text(text)
        assert secret not in out and n >= 1, text
    assert redact_text("python report.py --year 2026") == ("python report.py --year 2026", 0)


def test_interpreter_detection(tmp_path):
    assert interpreter_of("python3.13", "/usr/bin/python3.13", []) == "python"
    assert interpreter_of("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", []) == "powershell"
    assert interpreter_of("cmd.exe", None, []) == "cmd"
    assert interpreter_of("Finder", "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", []) is None
    assert interpreter_of("lua", "/usr/bin/lua", ["lua"]) == "lua"
    script = tmp_path / "job.py"
    script.write_text("print(1)")
    assert find_script("python", ["python", "-u", "job.py", "arg"], str(tmp_path)) == str(script)
    assert find_script("python", ["python", "-c", "print(1)"], str(tmp_path)) is None
    assert find_script("powershell", ["powershell.exe", "-File", str(script)], None) == str(script)


def test_spool_chain_and_rechain(tmp_path):
    spool = Spool(tmp_path / "s.db")
    a = spool.append({"event_id": "a"})
    b = spool.append({"event_id": "b"})
    assert (a["seq"], b["seq"]) == (1, 2)
    assert b["integrity"]["previous_hash"] == a["integrity"]["event_hash"]
    spool.rechain(10, "f" * 64)
    events = spool.pending(10)
    assert [e["seq"] for e in events] == [11, 12]
    assert events[0]["integrity"]["previous_hash"] == "f" * 64
    assert all(verify(e) for e in events) and spool.head()["seq"] == 12
    spool.ack(11)
    assert spool.count == 1


def test_teamviewer_log_line():
    rec = parse_teamviewer_line("123456789\tSOPORTE-PC\t09-11-2026 08:00:01\t09-11-2026 08:30:12\traul\tRemoteControl\t{ABC-1}\n")
    assert rec == {"partner_id": "123456789", "partner_name": "SOPORTE-PC", "start": "2026-11-09T08:00:01.000Z",
                   "end": "2026-11-09T08:30:12.000Z", "local_user": "raul", "mode": "RemoteControl", "guid": "ABC-1"}
    assert parse_teamviewer_line("not a session line") is None


_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_SYSMON_1 = f"""<Event xmlns='{_NS}'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID>
<TimeCreated SystemTime='2026-11-09T08:02:00.1234567Z'/><EventRecordID>77</EventRecordID></System><EventData>
<Data Name='UtcTime'>2026-11-09 08:02:00.123</Data><Data Name='ProcessId'>4521</Data>
<Data Name='Image'>C:\\Python313\\python.exe</Data><Data Name='CommandLine'>python.exe run.py --token abc</Data>
<Data Name='CurrentDirectory'>C:\\work\\</Data><Data Name='User'>PC\\operator</Data>
<Data Name='Hashes'>MD5=AA,SHA256=ABCDEF</Data><Data Name='ParentProcessId'>300</Data>
<Data Name='ParentImage'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
<Data Name='ParentCommandLine'>powershell.exe</Data></EventData></Event>"""
_SYSMON_11 = f"""<Event xmlns='{_NS}'><System><EventID>11</EventID><TimeCreated SystemTime='2026-11-09T08:04:00.0000000Z'/>
<EventRecordID>78</EventRecordID></System><EventData><Data Name='UtcTime'>2026-11-09 08:04:00.500</Data>
<Data Name='ProcessId'>4521</Data><Data Name='Image'>C:\\Python313\\python.exe</Data>
<Data Name='TargetFilename'>C:\\Documents\\report.csv</Data><Data Name='User'>PC\\operator</Data></EventData></Event>"""
_PS_4104 = f"""<Event xmlns='{_NS}'><System><EventID>4104</EventID><TimeCreated SystemTime='2026-11-09T08:02:30.5Z'/>
<EventRecordID>9</EventRecordID></System><EventData><Data Name='MessageNumber'>1</Data><Data Name='MessageTotal'>1</Data>
<Data Name='ScriptBlockText'>Invoke-WebRequest -Headers @{{Authorization='Bearer abcdefghijkl'}} https://x</Data>
<Data Name='ScriptBlockId'>id-1</Data><Data Name='Path'></Data></EventData></Event>"""
_LSM_21 = f"""<Event xmlns='{_NS}'><System><EventID>21</EventID><TimeCreated SystemTime='2026-11-09T08:00:00.000Z'/>
<EventRecordID>5</EventRecordID></System><UserData><EventXML xmlns='Event_NS'><User>PC\\operator</User>
<SessionID>3</SessionID><Address>203.0.113.7</Address></EventXML></UserData></Event>"""


def test_windows_event_log_mapping():
    recs = parse_events(_SYSMON_1 + _SYSMON_11)
    assert [r["record_id"] for r in recs] == [77, 78]
    proc = map_event(SYSMON, recs[0])
    assert proc["kind"] == "process" and proc["name"] == "python.exe" and proc["pid"] == 4521
    assert proc["parent"] == "powershell.exe" and proc["exe_sha256"] == "abcdef"
    assert proc["ts"] == "2026-11-09T08:02:00.123Z" and proc["user"] == "PC\\operator"
    created = map_event(SYSMON, recs[1])
    assert created["kind"] == "file_actor" and created["path"] == "C:\\Documents\\report.csv"
    block = map_event(POWERSHELL, parse_events(_PS_4104)[0])
    assert block["kind"] == "scriptblock" and "abcdefghijkl" not in block["data"]["text"]
    session = map_event(LSM, parse_events(_LSM_21)[0])
    assert session["event_type"] == "REMOTE_SESSION_STARTED" and session["data"]["remote_host"] == "203.0.113.7"
