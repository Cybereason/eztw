"""
Implementation of an entire file-activity tracker.
This is required because most events from Microsoft-Windows-Kernel-File do not hold the original opened
filename, but rather a "file object" that is given when the file is first open.
In addition, various translations and file-specific parsing is added.
"""
import os
import time
import string
import threading
import tempfile
from dataclasses import dataclass

import win32file

from .. import get_provider, consume_events, EztwDispatcher
from ..log import LOGGER


FILE_DIRECTORY_FILE = 0x00000001
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_DELETE_ON_CLOSE = 0x00001000

FileEndOfFileInformation = 20

# Get current drive letters mapping by iterating A to Z and using QueryDosDevice
DRIVE_LETTER_MAPPING = {}
for c in string.ascii_uppercase:
    try:
        p = win32file.QueryDosDevice(f"{c}:").rstrip('\x00')
        DRIVE_LETTER_MAPPING[p] = f"{c}:\\"
        LOGGER.info(f"Drive {c} is mapped to {p}")
    except:
        pass

if not DRIVE_LETTER_MAPPING:
    LOGGER.warning("No local drive mappings were found!")

# Given an NT path, translate it to a DOS path
# (i.e: \Device\HarddiskVolume1\bla\file.txt ==> c:\bla\file.txt)
def translate_path(nt_path):
    s = nt_path.split('\\')
    m = DRIVE_LETTER_MAPPING.get('\\'.join(s[:3]))
    if not m:
        # Could not translate
        return nt_path
    # Replace the prefix
    return m + '\\'.join(s[3:])

# Given bitmap instance and a mapping of flags, convert the int bitmap to a human readable string
def get_flags_from_bitmap(bitmap, flags):
    if bitmap == 0:
        return "<EMPTY 0x0>"
    res = []
    for mask, name in flags.items():
        if mask & bitmap:
            res.append(name)
    if not res:
        return f"<UNKNOWN {hex(bitmap)}>"
    else:
        return ' | '.join(res)

# Taken from: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-iocreatefileex
CREATE_OPTION_FLAGS = {
    0x00000001: "FILE_DIRECTORY_FILE",
    0x00000002: "FILE_WRITE_THROUGH",
    0x00000004: "FILE_SEQUENTIAL_ONLY",
    0x00000008: "FILE_NO_INTERMEDIATE_BUFFERING",
    0x00000010: "FILE_SYNCHRONOUS_IO_ALERT",
    0x00000020: "FILE_SYNCHRONOUS_IO_NONALERT",
    0x00000040: "FILE_NON_DIRECTORY_FILE",
    0x00000080: "FILE_CREATE_TREE_CONNECTION",
    0x00000100: "FILE_COMPLETE_IF_OPLOCKED",
    0x00000200: "FILE_NO_EA_KNOWLEDGE",
    0x00000400: "FILE_OPEN_REMOTE_INSTANCE",
    0x00000800: "FILE_RANDOM_ACCESS",
    0x00001000: "FILE_DELETE_ON_CLOSE",
    0x00002000: "FILE_OPEN_BY_FILE_ID",
    0x00004000: "FILE_OPEN_FOR_BACKUP_INTENT",
    0x00008000: "FILE_NO_COMPRESSION",
    0x00010000: "FILE_OPEN_REQUIRING_OPLOCK",
    0x00020000: "FILE_DISALLOW_EXCLUSIVE",
    0x00040000: "FILE_SESSION_AWARE",
    0x00100000: "FILE_RESERVE_OPFILTER",
    0x00200000: "FILE_OPEN_REPARSE_POINT",
    0x00400000: "FILE_OPEN_NO_RECALL",
    0x00800000: "FILE_OPEN_FOR_FREE_SPACE_QUERY",
}

# Get the string representation of file creation options
def get_create_options_flags(create_options):
    return get_flags_from_bitmap(create_options, CREATE_OPTION_FLAGS)

# Taken from https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
FILE_ATTRIBUTES_FLAGS = {
    0x1: "FILE_ATTRIBUTE_READONLY",
    0x2: "FILE_ATTRIBUTE_HIDDEN",
    0x4: "FILE_ATTRIBUTE_SYSTEM",
    0x10: "FILE_ATTRIBUTE_DIRECTORY",
    0x20: "FILE_ATTRIBUTE_ARCHIVE",
    0x40: "FILE_ATTRIBUTE_DEVICE",
    0x80: "FILE_ATTRIBUTE_NORMAL",
    0x100: "FILE_ATTRIBUTE_TEMPORARY",
    0x200: "FILE_ATTRIBUTE_SPARSE_FILE",
    0x400: "FILE_ATTRIBUTE_REPARSE_POINT",
    0x800: "FILE_ATTRIBUTE_COMPRESSED",
    0x1000: "FILE_ATTRIBUTE_OFFLINE",
    0x2000: "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED",
    0x4000: "FILE_ATTRIBUTE_ENCRYPTED",
    0x8000: "FILE_ATTRIBUTE_INTEGRITY_STREAM",
    0x10000: "FILE_ATTRIBUTE_VIRTUAL",
    0x20000: "FILE_ATTRIBUTE_NO_SCRUB_DATA",
    0x40000: "FILE_ATTRIBUTE_RECALL_ON_OPEN",
    0x80000: "FILE_ATTRIBUTE_PINNED",
    0x100000: "FILE_ATTRIBUTE_UNPINNED",
    0x400000: "FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS",
}

# Get the string representation of the file creation attributes
def get_create_attributes_flags(create_attributes):
    return get_flags_from_bitmap(create_attributes, FILE_ATTRIBUTES_FLAGS)

SHARE_ACCESS_FLAGS = {
    0x00000001: "FILE_SHARE_READ",
    0x00000002: "FILE_SHARE_WRITE",
    0x00000004: "FILE_SHARE_DELETE",
}

# Get the string representation of the file creation share access flags
def get_share_access_flags(share_access):
    return get_flags_from_bitmap(share_access, SHARE_ACCESS_FLAGS)

FILE_OVERWRITE = 0x00000004
FILE_OVERWRITE_IF = 0x00000005

DISPOSITION = {
    0x00000001: "FILE_OPEN",
    0x00000002: "FILE_CREATE",
    0x00000003: "FILE_OPEN_IF",
    0x00000004: "FILE_OVERWRITE",
    0x00000005: "FILE_OVERWRITE_IF",
}

# Get the string representation of the file creation disposition (this is not a bitmap...)
def get_create_disposition_flags(create_disposition):
    res = DISPOSITION.get(create_disposition)
    if not res:
        return "UNKNOWN"
    return res

@dataclass
class OpenedFile:
    """
    Represents an opened file
    """
    pid: int
    tid: int
    filename: str
    create_options: int
    create_disposition: int
    create_attributes: int
    shared_access: int


class FileEventsConsumer:
    """
    Consume the following events:
        Open (create) - 12
        Close - 14
        Read - 15
        Write - 16
        SetInformation - 17
        Delete - 26
        Rename - 27
        Created new file - 30

    Each dispatcher callback function eventually calls the "actual" function (to be implemented by subclasses),
    which receives in addition to the event record and parsed event also the relevant OpenedFile object
    """
    def __init__(self):
        # Maintain a map of OpenedFile instances by their file object
        self.opened_files_by_file_object = {}

    def run(self):
        provider = get_provider("Microsoft-Windows-Kernel-File")

        # Instantiate a dispatcher for the callbacks
        dispatcher = EztwDispatcher({
            provider.Event_Create_12: self.onFileOpen,
            provider.Event_Close_14: self.onFileClose,
            provider.Event_Read_15: self.onFileRead,
            provider.Event_Write_16: self.onFileWrite,
            provider.Event_SetInformation_17: self.onFileSetInformation,
            provider.Event_DeletePath_26: self.onFileDelete,
            provider.Event_RenamePath_27: self.onFileRename,
            provider.Event_CreateNewFile_30: self.onFileCreateNew,
        })

        # Consume events forever
        LOGGER.info("Consuming file events...")
        for event_record, parsed_event in consume_events(dispatcher.events):
            dispatcher(event_record, parsed_event)

    def onFileOpen(self, event_record, parsed_event):
        # Ignore directories
        if parsed_event.CreateOptions & FILE_DIRECTORY_FILE or parsed_event.CreateAttributes & FILE_ATTRIBUTE_DIRECTORY:
            return
        # Too few delimiters... this is a dir or a root
        n_delim = parsed_event.FileName.count("\\")
        if n_delim < 3 or (n_delim == 3 and parsed_event.FileName.endswith("\\")):
            return
        # This is a file being opened
        filename = translate_path(parsed_event.FileName)
        opened_file = OpenedFile(
            event_record.process_id,
            parsed_event.IssuingThreadId if hasattr(parsed_event, "IssuingThreadId") else 0,
            filename,
            parsed_event.CreateOptions & 0xFFFFFF,
            parsed_event.CreateOptions >> 24,
            parsed_event.CreateAttributes,
            parsed_event.ShareAccess)
        # Cache the object by the FileObject
        self.opened_files_by_file_object[parsed_event.FileObject] = opened_file
        self.fileOpened(event_record, parsed_event, opened_file)

    def fileOpened(self, event_record, parsed_event, opened_file):
        pass

    def onFileClose(self, event_record, parsed_event):
        # If the file object is unknown, ignore this event
        if (opened_file := self.opened_files_by_file_object.get(parsed_event.FileObject)) is None:
            return
        self.fileClosed(event_record, parsed_event, opened_file)
        # Remove this file object from the cache now it's closed
        self.opened_files_by_file_object.pop(parsed_event.FileObject)

    def fileClosed(self, event_record, parsed_event, opened_file):
        pass

    def onFileRead(self, event_record, parsed_event):
        if (opened_file := self.opened_files_by_file_object.get(parsed_event.FileObject)) is None:
            return
        self.fileRead(event_record, parsed_event, opened_file)

    def fileRead(self, event_record, parsed_event, opened_file):
        pass

    def onFileWrite(self, event_record, parsed_event):
        if (opened_file := self.opened_files_by_file_object.get(parsed_event.FileObject)) is None:
            return
        self.fileWritten(event_record, parsed_event, opened_file)

    def fileWritten(self, event_record, parsed_event, opened_file):
        pass

    def onFileSetInformation(self, event_record, parsed_event):
        if (opened_file := self.opened_files_by_file_object.get(parsed_event.FileObject)) is None:
            return
        # iff InfoClass is FileEndOfFileInformation and ExtraInformation is 0 - this is a truncation to empty
        if parsed_event.InfoClass == FileEndOfFileInformation and parsed_event.ExtraInformation == 0:
            self.fileTruncated(event_record, parsed_event, opened_file)
        else:
            self.fileSetInformation(event_record, parsed_event, opened_file)

    def fileTruncated(self, event_record, parsed_event, opened_file):
        pass

    def fileSetInformation(self, event_record, parsed_event, opened_file):
        pass

    def onFileDelete(self, event_record, parsed_event):
        if (opened_file := self.opened_files_by_file_object.get(parsed_event.FileObject)) is None:
            return
        self.fileDeleted(event_record, parsed_event, opened_file)
        # Note that the file is not actually deleted from the file system until the handle is closed

    def fileDeleted(self, event_record, parsed_event, opened_file):
        pass

    def onFileRename(self, event_record, parsed_event):
        if (opened_file := self.opened_files_by_file_object.get(parsed_event.FileObject)) is None:
            return
        # Also translate the new filename to DOS path
        self.fileRenamed(event_record, parsed_event, opened_file, translate_path(parsed_event.FilePath))

    def fileRenamed(self, event_record, parsed_event, opened_file, new_filename):
        pass

    def onFileCreateNew(self, event_record, parsed_event):
        if (opened_file := self.opened_files_by_file_object.get(parsed_event.FileObject)) is None:
            return
        self.fileCreated(event_record, parsed_event, opened_file)

    def fileCreated(self, event_record, parsed_event, opened_file):
        pass


class FileTracker(FileEventsConsumer):
    """
    An example of a FileEventsConsumer subclass which simply tracks files according to their (partial) name
    """
    def __init__(self, tracked_filenames):
        super().__init__()
        self.tracked_filenames = [x.lower() for x in tracked_filenames]

    def is_relevant_file(self, filename):
        # Check if the given filename is one we should track
        filename = filename.lower()
        return any(x in filename for x in self.tracked_filenames)

    def fileOpened(self, event_record, parsed_event, opened_file):
        if not self.is_relevant_file(opened_file.filename):
            return
        LOGGER.info(f"File {opened_file.filename} opened by PID {opened_file.pid}\n"
                    f"\tCreation options: {get_create_options_flags(opened_file.create_options)}")

    def fileClosed(self, event_record, parsed_event, opened_file):
        if not self.is_relevant_file(opened_file.filename):
            return
        LOGGER.info(f"File {opened_file.filename} was closed by PID {event_record.process_id}")

    def fileRead(self, event_record, parsed_event, opened_file):
        if not self.is_relevant_file(opened_file.filename):
            return
        LOGGER.info(
            f"File {opened_file.filename} was read by PID {event_record.process_id}"
            f" - {parsed_event.IOSize} bytes read"
        )

    def fileWritten(self, event_record, parsed_event, opened_file):
        if not self.is_relevant_file(opened_file.filename):
            return
        LOGGER.info(
            f"File {opened_file.filename} was written by PID {event_record.process_id}"
            f" - {parsed_event.IOSize} bytes written"
        )

    def fileTruncated(self, event_record, parsed_event, opened_file):
        if not self.is_relevant_file(opened_file.filename):
            return
        LOGGER.info(f"File {opened_file.filename} was truncated by PID {event_record.process_id}")

    def fileSetInformation(self, event_record, parsed_event, opened_file):
        if not self.is_relevant_file(opened_file.filename):
            return

    def fileDeleted(self, event_record, parsed_event, opened_file):
        if not self.is_relevant_file(opened_file.filename):
            return
        LOGGER.info(f"File {opened_file.filename} was deleted by PID {event_record.process_id}")

    def fileRenamed(self, event_record, parsed_event, opened_file, new_filename):
        if not self.is_relevant_file(opened_file.filename):
            return
        LOGGER.info(f"File {opened_file.filename} was renamed by PID {event_record.process_id} to {new_filename}")

    def fileCreated(self, event_record, parsed_event, opened_file):
        if not self.is_relevant_file(opened_file.filename):
            return
        LOGGER.info(f"File {opened_file.filename} is a new file created by PID {event_record.process_id}")

def delayed_file_activity(delay, filename):
    LOGGER.info(f"Thread started, sleeping for {delay} seconds...")
    time.sleep(delay)
    actual_filename = tempfile.mktemp(filename)
    LOGGER.info(f"Thread starting manipulations on temporary file '{actual_filename}'")
    with open(actual_filename, "wb") as fp:
        fp.write(b"Hello world!")
    time.sleep(1)
    with open(actual_filename, "rb") as fp:
        _ = fp.read()
    time.sleep(1)
    new_filename = actual_filename + ".new"
    os.rename(actual_filename, new_filename)
    time.sleep(1)
    os.truncate(new_filename, 0)
    time.sleep(1)
    os.remove(new_filename)

def main():
    # Create a delayed file-manipulation thread
    file_delay = 3  # Seconds
    filename = "_eztw_test"  # Base for temporary file name - this is also what we track
    LOGGER.info(f"Starting new thread. Manipulating {filename!r} in {file_delay} seconds...")
    threading.Thread(target=delayed_file_activity, args=(file_delay, filename)).start()

    # Start consuming events via FileTracker
    FileTracker(["eztw_test"]).run()

if __name__ == "__main__":
    main()
