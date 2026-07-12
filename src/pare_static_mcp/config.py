from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    jadx_path: str
    jadx_timeout_s: int
    jadx_stdout_cap: int          # bytes of jadx stdout to retain
    max_apk_bytes: int            # reject APKs larger than this before parsing
    max_zip_entries: int          # zip-bomb guard
    max_decompressed_bytes: int   # decompression-amplification guard

    @property
    def jadx_available(self) -> bool:
        from shutil import which
        return which(self.jadx_path) is not None or Path(self.jadx_path).is_file()


def load_config() -> Config:
    return Config(
        jadx_path=os.environ.get("JADX_PATH", "jadx"),
        jadx_timeout_s=int(os.environ.get("PARE_STATIC_JADX_TIMEOUT", 120)),
        jadx_stdout_cap=int(os.environ.get("PARE_STATIC_JADX_STDOUT_CAP", 4_000_000)),
        max_apk_bytes=int(os.environ.get("PARE_STATIC_MAX_APK_BYTES", 500 * 1024 * 1024)),
        max_zip_entries=int(os.environ.get("PARE_STATIC_MAX_ZIP_ENTRIES", 100_000)),
        max_decompressed_bytes=int(
            os.environ.get("PARE_STATIC_MAX_DECOMPRESSED_BYTES", 2 * 1024 * 1024 * 1024)
        ),
    )
