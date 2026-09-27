"""Image-wide browser kills are hardline; scoped usage still passes (trim)."""
from tools.approval import detect_dangerous_command, detect_hardline_command


def _is_hardline(cmd):
    blocked, _ = detect_hardline_command(cmd)
    return blocked


def test_taskkill_im_forms_blocked_with_pid_hint():
    for cmd in ("taskkill /F /IM chrome.exe",
                "taskkill /IM chrome",
                "taskkill.exe /F /IM msedge.exe",
                "taskkill /F /IM firefox.exe"):
        blocked, description = detect_hardline_command(cmd)
        assert blocked, cmd
        assert "taskkill /PID" in description


def test_taskkill_fi_filter_form_blocked():
    for cmd in ('taskkill /F /FI "IMAGENAME eq chrome.exe"',
                "taskkill /F /FI 'imagename eq firefox.exe'"):
        assert _is_hardline(cmd), cmd


def test_stop_process_forms_blocked():
    assert _is_hardline("Stop-Process -Name chrome -Force")
    assert _is_hardline("Stop-Process -Name chrome")


def test_pid_scoped_kill_still_allowed():
    # The safe form (tcs-social msg 6322/6324) keeps working: not hardline,
    # still surfaces as ordinary dangerous /F for approval.
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
