import ctypes
from ctypes import create_string_buffer, create_unicode_buffer, string_at, wstring_at
from ctypes import Structure, Union, POINTER
from ctypes import byref, pointer, cast
import ctypes.wintypes as wintypes
from winfsctl import *
from winfileinfo import *

CreateFile = ctypes.windll.kernel32.CreateFileW
GetFinalPathNameByHandle = ctypes.windll.kernel32.GetFinalPathNameByHandleW
CreateFile.restype = ctypes.c_void_p
CloseHandle = ctypes.windll.kernel32.CloseHandle
DeviceIoControl = ctypes.windll.kernel32.DeviceIoControl
GetLastError = ctypes.windll.kernel32.GetLastError
NtQueryDirectoryFile = ctypes.windll.ntdll.NtQueryDirectoryFile
NtQueryDirectoryFile.restype = ctypes.c_ulong

class SymbolicLinkReparseBuffer(Structure):
    _fields_ = [("SubstituteNameOffset", wintypes.USHORT),
                ("SubstituteNameLength", wintypes.USHORT),
                ("PrintNameOffset", wintypes.USHORT),
                ("PrintNameLength", wintypes.USHORT),
                ("Flags", wintypes.ULONG),
                ("PathBuffer", wintypes.WCHAR)]

class MountPointReparseBuffer(Structure):
    _fields_ = [("SubstituteNameOffset", wintypes.USHORT),
                ("SubstituteNameLength", wintypes.USHORT),
                ("PrintNameOffset", wintypes.USHORT),
                ("PrintNameLength", wintypes.USHORT),
                ("PathBuffer", wintypes.WCHAR)]

class GenericReparseBuffer(Structure):
    _fields_ = [("DataBuffer", ctypes.c_ubyte)]

class REPARSE_BUFFER(Union):
    _fields_ = [("SymbolicLink", SymbolicLinkReparseBuffer),
                ("MountPoint", MountPointReparseBuffer),
                ("Generic", GenericReparseBuffer)]

class REPARSE_DATA_BUFFER(Structure):
    _fields_ = [("ReparseTag", wintypes.ULONG),
                ("ReparseDataLength", wintypes.USHORT),
                ("Reserved", wintypes.USHORT),
                ("ReparseBuffer", REPARSE_BUFFER)]

class FILE_REPARSE_POINT_INFORMATION(Structure):
     _fields_ = [("FileReference", wintypes.c_longlong),
                 ("Tag", wintypes.ULONG)]

class FILE_REPARSE_POINT_INFORMATION(Structure):
     _fields_ = [("FileReference", wintypes.c_longlong),
                 ("Tag", wintypes.ULONG)]

class IO_STATUS_BLOCK(Structure):
    _fields_ = [("Pointer", wintypes.c_void_p),
                ("Information", wintypes.c_void_p)]


def AsType(ctype, buf):
    ctype_instance = cast(pointer(buf), POINTER(ctype)).contents
    return ctype_instance

SecurityAnonymous = 0
SecurityIdentification = 1
SecurityImpersonation = 2
SecurityDelegation = 3

SECURITY_ANONYMOUS        =  ( SecurityAnonymous      << 16 )
SECURITY_IDENTIFICATION   =  ( SecurityIdentification << 16 )
SECURITY_IMPERSONATION    =  ( SecurityImpersonation  << 16 )
SECURITY_DELEGATION       =  ( SecurityDelegation     << 16 )

FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
FILE_SHARE_DELETE = 0x4
FILE_SHARE_VALID_FLAGS = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE

FILE_ATTRIBUTE_READONLY           = 0x00000001  
FILE_ATTRIBUTE_HIDDEN             = 0x00000002  
FILE_ATTRIBUTE_SYSTEM             = 0x00000004  
FILE_ATTRIBUTE_DIRECTORY          = 0x00000010  
FILE_ATTRIBUTE_ARCHIVE            = 0x00000020  
FILE_ATTRIBUTE_DEVICE             = 0x00000040  
FILE_ATTRIBUTE_NORMAL             = 0x00000080  
FILE_ATTRIBUTE_TEMPORARY          = 0x00000100  
FILE_ATTRIBUTE_SPARSE_FILE        = 0x00000200  
FILE_ATTRIBUTE_REPARSE_POINT      = 0x00000400  
FILE_ATTRIBUTE_COMPRESSED         = 0x00000800  
FILE_ATTRIBUTE_OFFLINE            = 0x00001000  
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED= 0x00002000  
FILE_ATTRIBUTE_ENCRYPTED          = 0x00004000  
FILE_ATTRIBUTE_INTEGRITY_STREAM   = 0x00008000  
FILE_ATTRIBUTE_VIRTUAL            = 0x00010000  
FILE_ATTRIBUTE_NO_SCRUB_DATA      = 0x00020000  


FILE_READ_DATA            = 0x0001 
FILE_LIST_DIRECTORY       = 0x0001
FILE_WRITE_DATA           = 0x0002
FILE_ADD_FILE             = 0x0002
FILE_APPEND_DATA          = 0x0004
FILE_ADD_SUBDIRECTORY     = 0x0004
FILE_CREATE_PIPE_INSTANCE = 0x0004
FILE_READ_EA              = 0x0008
FILE_WRITE_EA             = 0x0010
FILE_EXECUTE              = 0x0020
FILE_TRAVERSE             = 0x0020
FILE_DELETE_CHILD         = 0x0040
FILE_READ_ATTRIBUTES      = 0x0080
FILE_WRITE_ATTRIBUTES     = 0x0100

GENERIC_READ              = (0x80000000)
GENERIC_WRITE             = (0x40000000)
GENERIC_EXECUTE           = (0x20000000)
GENERIC_ALL               = (0x10000000)


FILE_FLAG_WRITE_THROUGH      = 0x80000000
FILE_FLAG_OVERLAPPED         = 0x40000000
FILE_FLAG_NO_BUFFERING       = 0x20000000
FILE_FLAG_RANDOM_ACCESS      = 0x10000000
FILE_FLAG_SEQUENTIAL_SCAN    = 0x08000000
FILE_FLAG_DELETE_ON_CLOSE    = 0x04000000
FILE_FLAG_BACKUP_SEMANTICS   = 0x02000000
FILE_FLAG_POSIX_SEMANTICS    = 0x01000000
FILE_FLAG_SESSION_AWARE      = 0x00800000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_OPEN_NO_RECALL     = 0x00100000
FILE_FLAG_FIRST_PIPE_INSTANCE= 0x00080000

CREATE_NEW        =  1
CREATE_ALWAYS     =  2
OPEN_EXISTING     =  3
OPEN_ALWAYS       =  4
TRUNCATE_EXISTING =  5

if ctypes.sizeof(ctypes.c_void_p) == 8:
    INVALID_HANDLE_VALUE = 0xffffffffffffffff
else:
    INVALID_HANDLE_VALUE = 0xffffffff

DELETE                    = 0x00010000
READ_CONTROL              = 0x00020000
WRITE_DAC                 = 0x00040000
WRITE_OWNER               = 0x00080000

SYNCHRONIZE               = 0x100000
STANDARD_RIGHTS_REQUIRED  = 0xF0000

STANDARD_RIGHTS_READ      = READ_CONTROL
STANDARD_RIGHTS_WRITE     = READ_CONTROL
STANDARD_RIGHTS_EXECUTE   = READ_CONTROL

FILE_ALL_ACCESS  = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF)
FILE_GENERIC_READ = (STANDARD_RIGHTS_READ     |
                     FILE_READ_DATA           |
                     FILE_READ_ATTRIBUTES     |
                     FILE_READ_EA             |
                     SYNCHRONIZE)
FILE_GENERIC_WRITE = (STANDARD_RIGHTS_WRITE    |
                      FILE_WRITE_DATA          |
                      FILE_WRITE_ATTRIBUTES    |
                      FILE_WRITE_EA            |
                      FILE_APPEND_DATA         |
                      SYNCHRONIZE)
FILE_GENERIC_EXECUTE = (STANDARD_RIGHTS_EXECUTE  |
                        FILE_READ_ATTRIBUTES     |
                        FILE_EXECUTE             |
                        SYNCHRONIZE)

def raise_windows_error(err):
    raise WindowsError('%s Err: %d' % (wintypes.FormatError(err), err))

def IsReparseTagMicrosoft(tag):
    return bool(tag & 0x80000000)

def open_dir(filename):
    if not isinstance(filename, unicode):
        filename = unicode(filename, 'utf-8')
    handle = CreateFile(filename,
                         FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | SYNCHRONIZE,
                         FILE_SHARE_VALID_FLAGS,
                         None,
                         OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                         None)
    handle = ctypes.c_void_p(handle)
    if handle.value == INVALID_HANDLE_VALUE:
        raise_windows_error(GetLastError())
    return handle

def open_reparse_index(filename):
    if not isinstance(filename, unicode):
        filename = unicode(filename, 'utf-8')
    handle = CreateFile(filename,
                         GENERIC_READ,
                         FILE_SHARE_READ,
                         None,
                         OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS | SECURITY_IMPERSONATION,
                         None)
    handle = ctypes.c_void_p(handle)
    if handle.value == INVALID_HANDLE_VALUE:
        raise_windows_error(GetLastError())
    return handle

def open_file(filename):
    if not isinstance(filename, unicode):
        filename = unicode(filename, 'utf-8')
    handle = CreateFile(filename,
                         GENERIC_READ,
                         FILE_SHARE_VALID_FLAGS,
                         None,
                         OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                         None)
    handle = ctypes.c_void_p(handle)
    if handle.value == INVALID_HANDLE_VALUE:
        raise_windows_error(GetLastError())
    return handle

def get_reparse_point(handle):
    bytesReturned = ctypes.c_ulong(0)
    buffSize = ctypes.sizeof(REPARSE_DATA_BUFFER) + 256
    buff = create_string_buffer(buffSize)
    data_buff = AsType(REPARSE_DATA_BUFFER, buff)
    ret = DeviceIoControl(handle,
                        FSCTL_GET_REPARSE_POINT,
                        None,
                        0,
                        byref(data_buff),
                        buffSize,
                        byref(bytesReturned),
                        None)
    if not ret:
        raise_windows_error(GetLastError())
    return data_buff

def query_reparse_point(handle, restartScan=True):
    iostatus = IO_STATUS_BLOCK()
    rpinfo = FILE_REPARSE_POINT_INFORMATION()
    status = NtQueryDirectoryFile(handle,
                        None,
                        None,
                        None,
                        byref(iostatus),
                        byref(rpinfo),
                        ctypes.sizeof(FILE_REPARSE_POINT_INFORMATION),
                        FileReparsePointInformation,
                        True,
                        None,
                        restartScan
                        )

    if status != 0:
        raise WindowsError('status = 0x%x' % (status,))
    return rpinfo

def first_reparse_point_index(handle):
    return query_reparse_point(handle, True)

def next_reparse_point_index(handle):
    return query_reparse_point(handle, False)

def each_reparse_point(handle):
    yield first_reparse_point_index(handle)
    while True:
        try:
            next_rp = next_reparse_point_index(handle)
        except WindowsError:
            print 'finish'
            return
        else:
            yield next_rp


def get_symbolic_target(handle):
    data_buff = get_reparse_point(handle)
    offset = REPARSE_DATA_BUFFER.ReparseBuffer.offset + \
         SymbolicLinkReparseBuffer.PathBuffer.offset + \
         data_buff.ReparseBuffer.SymbolicLink.PrintNameOffset - 2 * ctypes.sizeof(ctypes.c_wchar)

    return wstring_at(byref(data_buff, offset), data_buff.ReparseBuffer.SymbolicLink.PrintNameLength/ctypes.sizeof(ctypes.c_wchar))

def close(handle):
    if not CloseHandle(handle):
        raise_windows_error(GetLastError())

class EXT_FILE_ID_128(Structure):
    _fields_ = [("LowPart", ctypes.c_ulonglong),
                ("HighPart", ctypes.c_ulonglong)]

class FILE_ID_INFO(Structure):
    _fields_ = [("VolumeSerialNumber", ctypes.c_ulonglong),
                ("FileId", EXT_FILE_ID_128)]

def get_file_id(abspath):
    file_id = FILE_ID_INFO()
    handle = open_file(abspath)
    ctypes.windll.kernel32.GetFileInformationByHandleEx(handle,
                                                        18,
                                                        byref(file_id),ctypes.sizeof(FILE_ID_INFO))
    close(handle)
    return (file_id.FileId.HighPart << EXT_FILE_ID_128.LowPart.size) + file_id.FileId.LowPart

handle = open_reparse_index(u'c:\\$Extend\\$Reparse:$R:$INDEX_ALLOCATION')
path_size = 128
buff = create_unicode_buffer(path_size)
GetFinalPathNameByHandle(handle, byref(buff), path_size, 0)
print buff.value
for idx, rp in enumerate(each_reparse_point(handle)):
    print 'Entry %d' % (idx,)
    print 'TagMicrosoft? %d' % (IsReparseTagMicrosoft(rp.Tag,))
    print 'Tag %x, FileReference: %x' % (rp.Tag, rp.FileReference)
close(handle)


