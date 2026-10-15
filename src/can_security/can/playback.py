"""
CAN Log Playback Engine.

Provides an interface to read and playback historical CAN bus logs
(e.g., .asc, .csv, .log) using python-can's LogReader.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from can_security.can.interface import CANInterface
from can_security.core.enums import ECUType
from can_security.core.exceptions import CANInterfaceError
from can_security.core.models import CANMessage

logger = logging.getLogger(__name__)


class LogPlaybackEngine:
    """
    Reads CAN messages from standard log files and yields them.
    Supports real-time playback or fast-forward analysis.
    """

    def __init__(self, file_path: str | Path, real_time: bool = False, playback_speed: float = 1.0):
        self.file_path = Path(file_path)
        self.real_time = real_time
        self.playback_speed = playback_speed
        self._active = False
        self._reader = None
        self._generator = None
        self._first_msg_time = None
        self._start_time = None

    def start(self) -> None:
        if not self.file_path.exists():
            raise CANInterfaceError(f"Log file not found: {self.file_path}")

        try:
            import can
            self._reader = can.LogReader(str(self.file_path))
            self._generator = iter(self._reader)
            self._active = True
            logger.info(f"Started playback of log file: {self.file_path.name}")
        except ImportError:
            raise CANInterfaceError("python-can library is not installed. Please install it.")
        except Exception as e:
            raise CANInterfaceError(f"Failed to open log file {self.file_path}: {e}") from e

    def stop(self) -> None:
        if self._reader is not None:
            try:
                self._reader.stop()
            except Exception:
                pass
        self._active = False
        logger.info("Log playback stopped")

    def receive(self, timeout: float | None = None) -> CANMessage | None:
        if not self._active or self._generator is None:
            return None

        try:
            can_msg = next(self._generator)
            
            # Handle real-time playback synchronization
            if self.real_time and can_msg.timestamp is not None:
                if self._first_msg_time is None:
                    self._first_msg_time = can_msg.timestamp
                    self._start_time = time.time()
                else:
                    # Calculate how long we should wait
                    elapsed_log_time = (can_msg.timestamp - self._first_msg_time) / max(0.1, self.playback_speed)
                    elapsed_real_time = time.time() - self._start_time
                    
                    sleep_time = elapsed_log_time - elapsed_real_time
                    if sleep_time > 0:
                        # Cap the sleep time to prevent hanging on huge gaps
                        sleep_time = min(sleep_time, timeout if timeout else 1.0)
                        time.sleep(sleep_time)

            return CANMessage(
                timestamp=time.time() if self.real_time else (can_msg.timestamp or time.time()),
                can_id=can_msg.arbitration_id,
                dlc=can_msg.dlc,
                data=bytes(can_msg.data),
                source_ecu=ECUType.UNKNOWN,
            )
        except StopIteration:
            self.stop()
            return None
        except Exception as e:
            logger.error(f"Error reading from log file: {e}")
            return None

    def is_active(self) -> bool:
        return self._active
