"""Chrome-only fallback: image-wide chrome kills are hardline; msedge/firefox stay dangerous."""
from tools.approval import detect_dangerous_command, detect_hardline_command


def _is_hardline(cmd):
    blocked, _ = detect_hardline_command(cmd)
    return blocked


def test_taskkill_im_chrome_blocked_with_pid_hint():
    for cmd in ("taskkill /F /IM chrome.exe",
                "taskkill /IM chrome"):
        blocked, description = detect_hardline_command(cmd)
        assert blocked, cmd
        assert "taskkill /PID" in description


def test_taskkill_fi_chrome_blocked():
    assert _is_hardline('taskkill /F /FI "IMAGENAME eq chrome.exe"')


def test_stop_process_chrome_blocked():
    assert _is_hardline("Stop-Process -Name chrome -Force")
    assert _is_hardline("Stop-Process -Name chrome")


def test_msedge_firefox_stay_dangerous_not_hardline():
    # Chrome-only scope: siblings stay on the old approvable path.
    for cmd in ("taskkill /F /IM msedge.exe",
                "taskkill /F /IM firefox.exe"):
        assert not _is_hardline(cmd), cmd
        dangerous, _, _ = detect_dangerous_command(cmd)
        assert dangerous, cmd


def test_pid_scoped_kill_still_allowed():
    assert not _is_hardline("taskkill /PID 47352 /F")
    dangerous, _, _ = detect_dangerous_command("taskkill /PID 47352 /F")
    assert dangerous
    assert not _is_hardline("Stop-Process -Id 46544")


def test_specialized_binaries_and_patterns_unaffected():
    assert not _is_hardline("taskkill /F /IM agent-browser.exe /T")
    assert not _is_hardline("taskkill /F /IM notepad.exe")
    assert not _is_hardline("taskkill /F /IM chromedriver.exe")


def test_quoted_prose_does_not_trip():
    assert not _is_hardline('echo "taskkill /IM chrome.exe scares me"')
