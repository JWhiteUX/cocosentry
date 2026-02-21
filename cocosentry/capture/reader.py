"""Async PCAP stream reader for WiFi Coconut pipe or pcap files."""

from __future__ import annotations

import asyncio
import logging
import sys
from collections.abc import AsyncIterator
from pathlib import Path

from scapy.layers.dot11 import Dot11, RadioTap
from scapy.utils import PcapReader

logger = logging.getLogger(__name__)


class PacketReader:
    """Reads pcap frames from stdin pipe or a pcap file.

    Usage:
        reader = PacketReader("-")  # stdin
        async for pkt in reader.packets():
            process(pkt)
    """

    def __init__(self, source: str = "-"):
        """Initialize reader.

        Args:
            source: "-" for stdin pipe, or path to a pcap file.
        """
        self.source = source
        self._stop = False

    def stop(self) -> None:
        """Signal the reader to stop."""
        self._stop = True

    def _open_reader(self) -> PcapReader:
        """Open the pcap source."""
        if self.source == "-":
            return PcapReader(sys.stdin.buffer)  # type: ignore[arg-type]
        path = Path(self.source)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {path}")
        return PcapReader(str(path))

    def _read_one(self, reader: PcapReader):
        """Read one packet, return None on EOF."""
        try:
            pkt = reader.read_packet()
            if pkt is None:
                return None
            # Only yield 802.11 frames
            if pkt.haslayer(Dot11):
                return pkt
            return "skip"  # sentinel: valid read but not 802.11
        except EOFError:
            return None
        except Exception as e:
            logger.debug("Packet read error: %s", e)
            return "skip"

    async def packets(self) -> AsyncIterator:
        """Yield parsed 802.11 frames with radiotap metadata.

        Uses asyncio.to_thread to avoid blocking the event loop on pcap reads.
        """
        reader = await asyncio.to_thread(self._open_reader)
        logger.info("PCAP reader opened: %s", self.source)

        try:
            while not self._stop:
                result = await asyncio.to_thread(self._read_one, reader)
                if result is None:
                    logger.info("PCAP source exhausted")
                    break
                if result == "skip":
                    continue
                yield result
        finally:
            try:
                reader.close()
            except Exception:
                pass
            logger.info("PCAP reader closed")
