import struct
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(slots=True)
class Packet:
    timestamp: datetime
    captured_length: int
    original_length: int
    data: bytes


class PCAPReader:
    def __init__(self, pcap_path, tshark_path=r"C:\Program Files\Wireshark\tshark.exe"):
        self.pcap_path = Path(pcap_path)
        self.tshark_path = Path(tshark_path)
        self._process = None
        self._stream = None
        self._stderr_file = None
        self._timestamp_resolution = None
        self._reached_eof = False
        self.packet_count = 0
        self.byte_order = None
        self.version_major = None
        self.version_minor = None
        self.snaplen = None
        self.link_type = None

    def __enter__(self):
        if not self.pcap_path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        if not self.tshark_path.is_file():
            raise FileNotFoundError(f"TShark executable not found: {self.tshark_path}")

        self._stderr_file = tempfile.TemporaryFile()

        try:
            self._process = subprocess.Popen([str(self.tshark_path), "-r", str(self.pcap_path), "-F", "pcap", "-w", "-"], stdout=subprocess.PIPE, stderr=self._stderr_file)
            self._stream = self._process.stdout
            self._read_global_header()

            return self

        except Exception:
            self._cleanup()
            raise

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if not self._reached_eof and self._process is not None:
                if self._process.poll() is None:
                    self._process.kill()
                self._process.wait()

                if self._stream is not None:
                    self._stream.close()
                    self._stream = None

                return

            if self._stream is not None:
                self._stream.close()
                self._stream = None

            if self._process is not None:
                return_code = self._process.wait()

                if return_code != 0 and exc_type is None:
                    error = self._read_tshark_error()
                    raise RuntimeError(f"TShark failed after {self.packet_count} packets: {error}")

        finally:
            self._cleanup()

    def __iter__(self):
        if self._stream is None:
            raise RuntimeError("PCAPReader must be used as a context manager.")

        while True:
            packet_header = self._stream.read(16)

            if not packet_header:
                self._reached_eof = True
                break

            if len(packet_header) != 16:
                raise ValueError(f"Incomplete PCAP packet header after {self.packet_count} packets.")

            ts_sec, ts_fraction, captured_length, original_length = struct.unpack(f"{self.byte_order}IIII", packet_header)

            packet_data = self._stream.read(captured_length)

            if len(packet_data) != captured_length:
                raise ValueError(f"Incomplete packet data after {self.packet_count} packets: expected {captured_length} bytes, got {len(packet_data)} bytes.")

            timestamp = self._build_timestamp(ts_sec, ts_fraction)

            self.packet_count += 1

            yield Packet(timestamp=timestamp, captured_length=captured_length, original_length=original_length, data=packet_data)

    def _read_global_header(self):
        global_header = self._stream.read(24)

        if len(global_header) != 24:
            raise ValueError("Incomplete PCAP global header from TShark.")

        magic = global_header[:4]

        if magic == b"\xd4\xc3\xb2\xa1":
            self.byte_order = "<"
            self._timestamp_resolution = "microsecond"
        elif magic == b"\xa1\xb2\xc3\xd4":
            self.byte_order = ">"
            self._timestamp_resolution = "microsecond"
        elif magic == b"\x4d\x3c\xb2\xa1":
            self.byte_order = "<"
            self._timestamp_resolution = "nanosecond"
        elif magic == b"\xa1\xb2\x3c\x4d":
            self.byte_order = ">"
            self._timestamp_resolution = "nanosecond"
        else:
            raise ValueError(f"Unsupported PCAP magic number from TShark: {magic.hex()}")

        _, self.version_major, self.version_minor, _, _, self.snaplen, self.link_type = struct.unpack(f"{self.byte_order}IHHiiII", global_header)

    def _build_timestamp(self, seconds, fraction):
        if self._timestamp_resolution == "microsecond":
            microseconds = fraction
        else:
            microseconds = fraction // 1000

        return datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=microseconds)

    def _read_tshark_error(self):
        if self._stderr_file is None:
            return "Unknown TShark error"

        self._stderr_file.seek(0)
        error = self._stderr_file.read().decode(errors="replace").strip()

        if not error:
            return "Unknown TShark error"

        return error.splitlines()[-1]

    def _cleanup(self):
        if self._stream is not None:
            self._stream.close()
            self._stream = None

        if self._process is not None:
            if self._process.poll() is None:
                self._process.kill()

            self._process.wait()
            self._process = None

        if self._stderr_file is not None:
            self._stderr_file.close()
            self._stderr_file = None