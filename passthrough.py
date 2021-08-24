#!/usr/bin/python3
"""A naive passthrough FUSE filesystem with tracing."""

from __future__ import with_statement

import errno
import logging
import os

import click
import psutil
from fuse import FUSE, FuseOSError, Operations, fuse_get_context
from logstash_async.formatter import LogstashFormatter
from logstash_async.handler import AsynchronousLogstashHandler
from logstash_async.transport import HttpTransport

TRACE_OPS = {"read", "readdir", "open", "write"}


class CPRLogstashFormatter(LogstashFormatter):
    """A simple override for the default LogstashFormatter."""

    def __init__(self, *args, **kwargs):
        """Defaults + uuid in the future."""
        super().__init__(*args, **kwargs)
        self._uuid = "instanceId"

    def _get_extra_fields(self, record):
        # ignore original extra_fields cause it's bunch of junk we don't need
        return {"instanceId": self._uuid}


class Passthrough(Operations):
    """A simple passthrough interface."""

    logger = logging.getLogger("fslog")

    def __init__(self, root, host="localhost", port=5959):
        """Initialize the filesystem.

        We mostly add custom logger and reported pids cache.
        """
        self.root = root
        self.host = host
        self.port = port
        self.reported_pids = set()

    def __call__(self, op, path, *args):
        if op in TRACE_OPS:
            uid, gid, pid = fuse_get_context()
            if pid not in self.reported_pids and pid > 0:
                p = psutil.Process(pid)
                extra = {"ppid": pid, "self": str(p), "parent": str(p.parent())}
                self.logger.info("Process operating on filesystem", extra=extra)
                self.reported_pids.add(pid)

            self.logger.info("%s(%s)", op, repr(args), extra={"ppid": pid})

        ret = "[Unhandled Exception]"
        try:
            ret = getattr(self, op)(path, *args)
            return ret
        except OSError as e:
            ret = str(e)
            raise

    def init(self, path):
        transport = HttpTransport(self.host, self.port, timeout=5.0, ssl_enable=False)

        self.handler = AsynchronousLogstashHandler(
            self.host,
            self.port,
            transport=transport,
            database_path="/tmp/foo.db",
        )

        logstash_formatter = CPRLogstashFormatter(
            message_type="python-logstash", extra_prefix="cpr"
        )
        self.handler.setFormatter(logstash_formatter)

        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(self.handler)

    def destroy(self, path):
        """Clean up any resources used by the filesystem."""
        self.handler.flush()  # TODO it's not guaranteed to succeed...
        pass

    def _full_path(self, partial):
        """Calculate full path for the mounted file system."""
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    def access(self, path, mode):
        """Access a file."""
        full_path = self._full_path(path)
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    def chmod(self, path, mode):
        """Change a file's permissions."""
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    def chown(self, path, uid, gid):
        """Change a file's owernship."""
        full_path = self._full_path(path)
        return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        """Return file attributes."""
        full_path = self._full_path(path)
        st = os.lstat(full_path)
        return dict(
            (key, getattr(st, key))
            for key in (
                "st_atime",
                "st_ctime",
                "st_gid",
                "st_mode",
                "st_mtime",
                "st_nlink",
                "st_size",
                "st_uid",
            )
        )

    def readdir(self, path, fh):
        """Read a directory."""
        full_path = self._full_path(path)

        dirents = [".", ".."]
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        for r in dirents:
            yield r

    def readlink(self, path):
        """Read a symbolic link."""
        pathname = os.readlink(self._full_path(path))
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    def mknod(self, path, mode, dev):
        """Make a special file."""
        return os.mknod(self._full_path(path), mode, dev)

    def rmdir(self, path):
        """Remove a directory."""
        full_path = self._full_path(path)
        return os.rmdir(full_path)

    def mkdir(self, path, mode):
        """Make a directory."""
        return os.mkdir(self._full_path(path), mode)

    def statfs(self, path):
        """Get fs stats."""
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        return dict(
            (key, getattr(stv, key))
            for key in (
                "f_bavail",
                "f_bfree",
                "f_blocks",
                "f_bsize",
                "f_favail",
                "f_ffree",
                "f_files",
                "f_flag",
                "f_frsize",
                "f_namemax",
            )
        )

    def unlink(self, path):
        """Unlink a file."""
        return os.unlink(self._full_path(path))

    def symlink(self, target, name):
        """Create a symbolic link."""
        return os.symlink(self._full_path(target), self._full_path(name))

    def rename(self, old, new):
        """Rename a file."""
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        """Create a hard link."""
        return os.link(self._full_path(target), self._full_path(name))

    def utimens(self, path, times=None):
        """Get utime for a path."""
        return os.utime(self._full_path(path), times)

    def open(self, path, flags):
        """Open a file."""
        full_path = self._full_path(path)
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        """Create and open a file."""
        full_path = self._full_path(path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
        """Read from a file."""
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, length)

    def write(self, path, buf, offset, fh):
        """Write to a file."""
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    def truncate(self, path, length, fh=None):
        """Truncate a file."""
        full_path = self._full_path(path)
        with open(full_path, "r+") as f:
            f.truncate(length)

    def flush(self, path, fh):
        """Flush buffered information."""
        return os.fsync(fh)

    def release(self, path, fh):
        """Release is called when FUSE is done with a file."""
        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        """Flush any dirty information to disk."""
        return self.flush(path, fh)


@click.command()
@click.argument("src", nargs=1, type=click.Path(exists=True))
@click.argument("dst", nargs=1)
def passthrough(src, dst):
    """Mount host directory SRC to DST."""
    if not os.path.isdir(dst):
        os.mkdir(dst)

    FUSE(
        Passthrough(src),
        dst,
        foreground=False,
        ro=True,
        allow_other=True,
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    passthrough()
