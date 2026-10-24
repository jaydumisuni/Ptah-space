"""Fail-closed Windows NTFS custody checks for E07's disposable carrier state.

This module is imported only on Windows. It uses Win32 security descriptors,
not POSIX mode bits or localized icacls output. This is a pre-open admission
check, not a race-free handle/dirfd custody or an independent E07 release proof.
"""
import ctypes
from ctypes import wintypes
import os


class _AceHeader(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ubyte), ("flags", ctypes.c_ubyte),
                ("size", ctypes.c_ushort)]


class _AclSize(ctypes.Structure):
    _fields_ = [("ace_count", wintypes.DWORD),
                ("acl_bytes_in_use", wintypes.DWORD),
                ("acl_bytes_free", wintypes.DWORD)]


def validate_private_windows(path):
    """Require current-user ownership and a DACL without other allow trustees.

    SYSTEM and BUILTIN\\Administrators are trusted Windows OS principals.
    Inherit-only ACEs do not grant access to this object. Unknown effective
    ACE types are rejected rather than interpreted optimistically.
    """
    if os.name != "nt":
        raise RuntimeError("Windows ACL validation requires Windows")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    ptr = ctypes.c_void_p
    dword_ptr = ctypes.POINTER(wintypes.DWORD)
    advapi.OpenProcessToken.argtypes = [ptr, wintypes.DWORD, ctypes.POINTER(ptr)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [ptr, wintypes.DWORD, ptr,
                                           wintypes.DWORD, dword_ptr]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, wintypes.DWORD,
                                              wintypes.DWORD, ctypes.POINTER(ptr),
                                              ptr, ctypes.POINTER(ptr), ptr,
                                              ctypes.POINTER(ptr)]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.GetAclInformation.argtypes = [ptr, ptr, wintypes.DWORD, wintypes.DWORD]
    advapi.GetAclInformation.restype = wintypes.BOOL
    advapi.GetAce.argtypes = [ptr, wintypes.DWORD, ctypes.POINTER(ptr)]
    advapi.GetAce.restype = wintypes.BOOL
    advapi.EqualSid.argtypes = [ptr, ptr]
    advapi.EqualSid.restype = wintypes.BOOL
    advapi.CreateWellKnownSid.argtypes = [wintypes.DWORD, ptr, ptr, dword_ptr]
    advapi.CreateWellKnownSid.restype = wintypes.BOOL
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = ptr
    kernel.CloseHandle.argtypes = [ptr]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ptr]
    kernel.LocalFree.restype = ptr

    def check(ok, what):
        if not ok:
            raise ValueError("Windows carrier custody " + what + " failed: " +
                             str(ctypes.get_last_error()))

    token = ptr()
    check(advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008,
                                  ctypes.byref(token)), "token")
    descriptor = ptr()
    try:
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not needed.value or needed.value > 65536:
            raise ValueError("Windows carrier custody token size invalid")
        user_info = ctypes.create_string_buffer(needed.value)
        check(advapi.GetTokenInformation(token, 1, user_info, needed,
                                         ctypes.byref(needed)), "token SID")
        user_sid = ctypes.cast(user_info, ctypes.POINTER(ptr))[0]
        trusted = [user_sid]
        # WinLocalSystemSid=22; WinBuiltinAdministratorsSid=26.
        sid_buffers = []
        # OWNER RIGHTS (71) grants rights only to the verified object owner.\n        # It is present on Python 3.11+ Windows mkdir-created directories\n        # and can be inherited by the database and SQLite sidecars.\n        for sid_type in (22, 26, 71):
            sid_buffer = ctypes.create_string_buffer(68)
            sid_length = wintypes.DWORD(len(sid_buffer))
            check(advapi.CreateWellKnownSid(sid_type, None, sid_buffer,
                                            ctypes.byref(sid_length)), "system SID")
            sid_buffers.append(sid_buffer)
            trusted.append(ctypes.cast(sid_buffer, ptr).value)

        owner = ptr()
        dacl = ptr()
        error = advapi.GetNamedSecurityInfoW(str(path), 1, 0x0001 | 0x0004,
                                             ctypes.byref(owner), None,
                                             ctypes.byref(dacl), None,
                                             ctypes.byref(descriptor))
        if error:
            raise ValueError("Windows carrier custody descriptor failed: " + str(error))
        if not owner.value or not advapi.EqualSid(owner, user_sid):
            raise ValueError("private carrier owner required")
        # A NULL DACL grants everyone access. An empty DACL denies everyone
        # and is acceptable to admission (subsequent I/O may fail closed).
        if not dacl.value:
            raise ValueError("private carrier Windows DACL required")
        info = _AclSize()
        check(advapi.GetAclInformation(dacl, ctypes.byref(info),
                                       ctypes.sizeof(info), 2), "ACL size")
        if info.ace_count > 4096:
            raise ValueError("private carrier Windows DACL too large")
        for index in range(info.ace_count):
            ace = ptr()
            check(advapi.GetAce(dacl, index, ctypes.byref(ace)), "ACE read")
            header = ctypes.cast(ace, ctypes.POINTER(_AceHeader)).contents
            if header.size < 8:
                raise ValueError("private carrier Windows ACE malformed")
            if header.flags & 0x08:  # INHERIT_ONLY_ACE
                continue
            if header.type == 1:  # ACCESS_DENIED_ACE_TYPE
                continue
            if header.type != 0:  # only plain ACCESS_ALLOWED_ACE is admitted
                raise ValueError("private carrier Windows ACE type unsupported")
            ace_sid = ace.value + 8  # ACE_HEADER(4) + ACCESS_MASK(4)
            if not any(advapi.EqualSid(ace_sid, sid) for sid in trusted):
                raise ValueError("private carrier Windows ACL grants other principals")
    finally:
        if descriptor.value:
            kernel.LocalFree(descriptor)
        kernel.CloseHandle(token)
