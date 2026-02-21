"""Radiotap header parser helpers."""

from __future__ import annotations

from dataclasses import dataclass

from scapy.layers.dot11 import RadioTap


@dataclass
class RadiotapInfo:
    """Extracted radiotap metadata."""

    channel_freq: int | None = None
    channel: int | None = None
    rssi: int | None = None  # dBm
    antenna: int | None = None
    flags: int | None = None

    @property
    def is_fcs_valid(self) -> bool | None:
        """Check if FCS flag indicates valid checksum."""
        if self.flags is None:
            return None
        return bool(self.flags & 0x10)  # FCS at end flag


# 2.4GHz channel center frequencies
CHANNEL_FREQ_MAP: dict[int, int] = {
    2412: 1, 2417: 2, 2422: 3, 2427: 4, 2432: 5, 2437: 6, 2442: 7,
    2447: 8, 2452: 9, 2457: 10, 2462: 11, 2467: 12, 2472: 13, 2484: 14,
}


def freq_to_channel(freq: int) -> int | None:
    """Convert frequency in MHz to 2.4GHz channel number."""
    return CHANNEL_FREQ_MAP.get(freq)


def extract_radiotap(pkt) -> RadiotapInfo:
    """Extract radiotap fields from a scapy packet."""
    info = RadiotapInfo()

    if not pkt.haslayer(RadioTap):
        return info

    rt = pkt[RadioTap]

    # Channel frequency
    if hasattr(rt, "ChannelFrequency") and rt.ChannelFrequency:
        info.channel_freq = rt.ChannelFrequency
        info.channel = freq_to_channel(rt.ChannelFrequency)

    # Signal strength (dBm)
    if hasattr(rt, "dBm_AntSignal") and rt.dBm_AntSignal is not None:
        info.rssi = rt.dBm_AntSignal

    # Antenna index
    if hasattr(rt, "Antenna") and rt.Antenna is not None:
        info.antenna = rt.Antenna

    # Flags
    if hasattr(rt, "Flags") and rt.Flags is not None:
        info.flags = int(rt.Flags)

    return info
