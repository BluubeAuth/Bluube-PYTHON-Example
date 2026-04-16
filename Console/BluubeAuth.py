import base64
import json
import ctypes
import os
import ctypes.wintypes
import platform
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
import requests

class _SecurityError(Exception):
    pass

def _hex_to_bytes(hex_str: str) -> bytes:
    s = hex_str.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return bytes.fromhex(s)

def _normalize_base(api_base_url: Optional[str]) -> str:
    base = (api_base_url or "https://api.bluube.com").strip().rstrip("/")
    if base.endswith("/api/client"):
        base = base[: -len("/api/client")]
    return base + "/api/client"

def _ensure_secure_base_url(url: str) -> None:
    if not url.lower().startswith("https://"):
        raise RuntimeError("Bluube SDK requires an HTTPS endpoint.")

@dataclass
class ApiResponse:
    success: bool
    message: Optional[str] = None
    sessionId: Optional[str] = None
    publicKey: Optional[str] = None
    code: Optional[str] = None
    user_data: Optional[Dict[str, Any]] = None

class BluubeAuth:
    SIGNATURE_MAX_SKEW_SECONDS = 600
    PINNED_SERVER_PUBLIC_KEY = _hex_to_bytes("f86ac4fb026c6f58159e3d4e8d807ff17c96151cc4b7a8b0624d4e9a1e072bb8")

    def __init__(self, app_id: str, owner_id: str, version: str, api_base_url: Optional[str] = None) -> None:
        self.app_id = app_id
        self.owner_id = owner_id
        self.version = version or "1.0"
        self.api_url = _normalize_base(api_base_url)
        _ensure_secure_base_url(self.api_url)

        self._session = requests.Session()
        self._session.headers["User-Agent"] = "BluubeAuth-Python"
        self.timeout_seconds = 15

        self.session_id: Optional[str] = None
        self.is_initialized = False
        self.is_authenticated = False
        self.last_message: Optional[str] = None
        self.user_data: Optional[Dict[str, Any]] = None

        self._heartbeat_interval_seconds = 30
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._last_valid_heartbeat_at: Optional[float] = None

        self._cached_public_ip: Optional[str] = None
        self._cached_public_ip_expires_at: float = 0.0

        self._verify_key = VerifyKey(self.PINNED_SERVER_PUBLIC_KEY)
        self._hwid = (self._get_hwid() or "").strip()

    @property
    def last_valid_heartbeat_at(self) -> Optional[float]:
        return self._last_valid_heartbeat_at

    def set_heartbeat_interval(self, seconds: float) -> None:
        if seconds <= 0:
            raise ValueError("Invalid interval")
        self._heartbeat_interval_seconds = int(seconds)

    def close(self) -> None:
        try:
            self.logout()
        except Exception:
            self._stop_heartbeat()
        try:
            self._session.close()
        except Exception:
            pass

    def _get_public_ip_cached(self) -> Optional[str]:
        now = time.time()
        if self._cached_public_ip and now < self._cached_public_ip_expires_at:
            return self._cached_public_ip
        try:
            r = self._session.get("https://api4.ipify.org", timeout=5)
            ip = (r.text or "").strip()
            if ip:
                self._cached_public_ip = ip
                self._cached_public_ip_expires_at = now + 600.0
                return ip
        except Exception:
            return self._cached_public_ip
        return self._cached_public_ip

    def _get_hwid(self) -> Optional[str]:
        system = platform.system().lower()
        if system == "windows":
            sid = self._get_windows_user_sid()
            if sid:
                return sid

            try:
                import winreg

                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                    value, _ = winreg.QueryValueEx(key, "MachineGuid")
                    if isinstance(value, str) and value.strip():
                        return value.strip()
            except Exception:
                pass

            try:
                out = subprocess.check_output(
                    ["wmic", "csproduct", "get", "uuid"],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=3,
                )
                lines = [ln.strip() for ln in out.splitlines() if ln.strip() and "UUID" not in ln.upper()]
                if lines and lines[0]:
                    return lines[0]
            except Exception:
                pass

        if system == "linux":
            for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        v = f.read().strip()
                        if v:
                            return v
                except Exception:
                    pass

        if system == "darwin":
            try:
                out = subprocess.check_output(
                    ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=3,
                )
                for line in out.splitlines():
                    if "IOPlatformUUID" in line:
                        parts = line.split("=", 1)
                        if len(parts) == 2:
                            v = parts[1].strip().strip('"')
                            if v:
                                return v
            except Exception:
                pass

        try:
            node = uuid.getnode()
            if node:
                return hex(node)
        except Exception:
            pass

        return None

    def _get_windows_user_sid(self) -> Optional[str]:
        try:
            advapi32 = ctypes.windll.advapi32
            kernel32 = ctypes.windll.kernel32

            TokenUser = 1
            TOKEN_QUERY = 0x0008

            class SID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [("Sid", ctypes.wintypes.LPVOID), ("Attributes", ctypes.wintypes.DWORD)]

            class TOKEN_USER(ctypes.Structure):
                _fields_ = [("User", SID_AND_ATTRIBUTES)]

            OpenProcessToken = advapi32.OpenProcessToken
            OpenProcessToken.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.HANDLE)]
            OpenProcessToken.restype = ctypes.wintypes.BOOL

            GetTokenInformation = advapi32.GetTokenInformation
            GetTokenInformation.argtypes = [
                ctypes.wintypes.HANDLE,
                ctypes.wintypes.DWORD,
                ctypes.wintypes.LPVOID,
                ctypes.wintypes.DWORD,
                ctypes.POINTER(ctypes.wintypes.DWORD),
            ]
            GetTokenInformation.restype = ctypes.wintypes.BOOL

            ConvertSidToStringSidW = advapi32.ConvertSidToStringSidW
            ConvertSidToStringSidW.argtypes = [ctypes.wintypes.LPVOID, ctypes.POINTER(ctypes.wintypes.LPWSTR)]
            ConvertSidToStringSidW.restype = ctypes.wintypes.BOOL

            LocalFree = kernel32.LocalFree
            LocalFree.argtypes = [ctypes.wintypes.HLOCAL]
            LocalFree.restype = ctypes.wintypes.HLOCAL

            h_token = ctypes.wintypes.HANDLE()
            if not OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(h_token)):
                return None

            try:
                size = ctypes.wintypes.DWORD(0)
                GetTokenInformation(h_token, TokenUser, None, 0, ctypes.byref(size))
                if size.value == 0:
                    return None

                buf = ctypes.create_string_buffer(size.value)
                if not GetTokenInformation(h_token, TokenUser, buf, size, ctypes.byref(size)):
                    return None

                token_user = ctypes.cast(buf, ctypes.POINTER(TOKEN_USER)).contents
                sid_ptr = token_user.User.Sid
                if not sid_ptr:
                    return None

                sid_str_ptr = ctypes.wintypes.LPWSTR()
                if not ConvertSidToStringSidW(sid_ptr, ctypes.byref(sid_str_ptr)):
                    return None

                try:
                    sid_str = ctypes.wstring_at(sid_str_ptr)
                finally:
                    LocalFree(sid_str_ptr)

                if isinstance(sid_str, str) and sid_str.strip():
                    return sid_str.strip()
                return None
            finally:
                try:
                    kernel32.CloseHandle(h_token)
                except Exception:
                    pass
        except Exception:
            return None

    def _verify_response(self, raw_body: str, headers: Dict[str, str]) -> None:
        sig = headers.get("X-Bluube-Signature")
        ts = headers.get("X-Bluube-Timestamp")
        if not sig or not ts:
            raise _SecurityError("Missing signature")
        try:
            ts_int = int(ts)
        except Exception:
            raise _SecurityError("Invalid timestamp")

        now = int(time.time())
        if abs(now - ts_int) > self.SIGNATURE_MAX_SKEW_SECONDS:
            raise _SecurityError("Response expired")

        try:
            signature = base64.b64decode(sig)
        except Exception:
            raise _SecurityError("Invalid signature")

        msg = (ts + raw_body).encode("utf-8")
        try:
            self._verify_key.verify(msg, signature)
        except BadSignatureError:
            raise _SecurityError("Integrity check failed")

    def _post(self, path: str, payload: Dict[str, Any]) -> ApiResponse:
        url = self.api_url + path
        r = self._session.post(url, json=payload, timeout=self.timeout_seconds)
        raw = r.text or ""
        self._verify_response(raw, dict(r.headers))
        data = json.loads(raw) if raw else {}
        return ApiResponse(
            success=bool(data.get("success")),
            message=data.get("message"),
            sessionId=data.get("sessionId") or data.get("session", {}).get("id"),
            publicKey=data.get("publicKey"),
            code=data.get("code"),
            user_data=data.get("user"),
        )

    def initialize(self) -> bool:
        try:
            ip = self._get_public_ip_cached()
            res = self._post(
                "/initialize",
                {"appId": self.app_id, "ownerId": self.owner_id, "version": self.version, "ip": ip},
            )

            if res.success:
                self.session_id = res.sessionId
                if res.publicKey:
                    try:
                        received = base64.b64decode(res.publicKey)
                        if received != self.PINNED_SERVER_PUBLIC_KEY:
                            raise _SecurityError("Server public key mismatch")
                    except Exception:
                        raise _SecurityError("Server public key mismatch")
                self.is_initialized = True
                self.is_authenticated = False
                self.last_message = res.message or "OK"
                self._start_heartbeat()
                return True

            self.last_message = res.message or "Initialization failed."
            return False
        except _SecurityError as ex:
            self._terminate(f"Security error: {str(ex)}")
            return False
        except requests.RequestException:
            self.last_message = "Network error."
            return False
        except Exception as ex:
            self.last_message = f"Initialization error: {str(ex)}"
            return False

    def login_user(self, username: str, password: str, hwid: Optional[str] = None) -> bool:
        if not self.is_initialized or not self.session_id:
            self.last_message = "Call initialize() first."
            return False
        try:
            ip = self._get_public_ip_cached()
            hwid_value = (hwid or self._hwid).strip() if (hwid or self._hwid) else ""
            payload = {
                "sessionId": self.session_id,
                "appId": self.app_id,
                "ownerId": self.owner_id,
                "version": self.version,
                "username": username,
                "password": password,
                "ip": ip,
            }
            if hwid_value:
                payload["hwid"] = hwid_value

            res = self._post(
                "/auth/login",
                payload,
            )
            self.last_message = res.message
            if res.success:
                self.is_authenticated = True
                self.user_data = res.user_data
                return True
            return False
        except _SecurityError as ex:
            self._terminate(f"Security error: {str(ex)}")
            return False
        except requests.RequestException:
            self.last_message = "Network error."
            return False
        except Exception as ex:
            self.last_message = f"Login error: {str(ex)}"
            return False

    def register_with_key(self, key: str, username: str, password: str, hwid: Optional[str] = None) -> bool:
        if not self.is_initialized or not self.session_id:
            self.last_message = "Call initialize() first."
            return False
        try:
            ip = self._get_public_ip_cached()
            hwid_value = (hwid or self._hwid).strip() if (hwid or self._hwid) else ""
            payload = {
                "sessionId": self.session_id,
                "appId": self.app_id,
                "ownerId": self.owner_id,
                "version": self.version,
                "licenseKey": key,
                "username": username,
                "password": password,
                "ip": ip,
            }
            if hwid_value:
                payload["hwid"] = hwid_value

            res = self._post(
                "/auth/register",
                payload,
            )
            self.last_message = res.message
            if res.success:
                self.is_authenticated = True
                self.user_data = res.user_data
                return True
            return False
        except _SecurityError as ex:
            self._terminate(f"Security error: {str(ex)}")
            return False
        except requests.RequestException:
            self.last_message = "Network error."
            return False
        except Exception as ex:
            self.last_message = f"Registration error: {str(ex)}"
            return False

    def logout(self) -> None:
        self._stop_heartbeat()
        if not self.is_initialized or not self.session_id:
            return
        try:
            self._post("/logout", {"sessionId": self.session_id})
        except Exception:
            pass
        self.is_initialized = False
        self.is_authenticated = False
        self.session_id = None
        self.user_data = None
        self._last_valid_heartbeat_at = None

    def _heartbeat_tick(self) -> None:
        if not self.is_initialized or not self.session_id:
            return
        try:
            ip = self._get_public_ip_cached()
            payload = {"sessionId": self.session_id, "ip": ip, "version": self.version}
            if self._hwid:
                payload["hwid"] = self._hwid
            res = self._post("/heartbeat", payload)
            if not res.success:
                if (res.message or "").strip().casefold() == "invalid session":
                    os._exit(0)
                self._terminate(res.message or "Session terminated.")
            self._last_valid_heartbeat_at = time.time()
        except _SecurityError as ex:
            self._terminate(f"Security error: {str(ex)}")
        except requests.RequestException:
            os._exit(0)

    def _start_heartbeat(self) -> None:
        self._stop_heartbeat()
        self._heartbeat_stop.clear()

        def loop() -> None:
            while not self._heartbeat_stop.is_set():
                try:
                    self._heartbeat_tick()
                except SystemExit:
                    raise
                except Exception:
                    os._exit(0)
                self._heartbeat_stop.wait(self._heartbeat_interval_seconds)

        t = threading.Thread(target=loop, daemon=True)
        self._heartbeat_thread = t
        t.start()

    def _stop_heartbeat(self) -> None:
        self._heartbeat_stop.set()
        self._heartbeat_thread = None

    def _terminate(self, message: str) -> None:
        self._stop_heartbeat()
        os._exit(1)
