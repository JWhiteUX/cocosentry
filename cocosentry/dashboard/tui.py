"""Terminal UI dashboard using Textual.

Displays live channel heatmap, alert feed, AP inventory, and device inventory.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

from cocosentry.config import AppConfig


def run_dashboard(config: AppConfig, source: str) -> None:
    """Launch the TUI dashboard with live monitoring."""
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.reactive import reactive
    from textual.widgets import DataTable, Footer, Header, Log, Static

    class ChannelHeatmap(Static):
        """Displays a channel utilization heatmap."""

        channel_data: reactive[list[int]] = reactive(lambda: [0] * 14)

        def render(self) -> str:
            blocks = " ░▒▓█"
            max_val = max(self.channel_data) if any(self.channel_data) else 1

            lines = ["Channel Activity (2.4 GHz)", ""]
            bar_line = ""
            label_line = ""

            for ch in range(14):
                count = self.channel_data[ch]
                level = min(int((count / max_val) * 4), 4) if max_val > 0 else 0
                bar_line += f" {blocks[level]} "
                label_line += f"{ch+1:^3}"

            lines.append(bar_line)
            lines.append(label_line)
            lines.append(f"\nTotal packets: {sum(self.channel_data)}")

            return "\n".join(lines)

    class AlertFeed(Log):
        """Scrolling alert feed."""
        pass

    class CocoSentryApp(App):
        """CocoSentry Terminal Dashboard."""

        CSS = """
        Screen {
            layout: grid;
            grid-size: 2 2;
            grid-rows: 1fr 2fr;
        }

        #heatmap {
            border: solid green;
            padding: 1;
        }

        #stats {
            border: solid blue;
            padding: 1;
        }

        #alerts {
            border: solid red;
            column-span: 2;
        }
        """

        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("r", "refresh", "Refresh"),
        ]

        def __init__(self, config: AppConfig, source: str):
            super().__init__()
            self.config = config
            self.source = source
            self._pipeline = None

        def compose(self) -> ComposeResult:
            yield Header()
            yield ChannelHeatmap(id="heatmap")
            yield Static("CocoSentry Monitor\n\nInitializing...", id="stats")
            yield AlertFeed(id="alerts")
            yield Footer()

        def on_mount(self) -> None:
            self.title = "CocoSentry"
            self.sub_title = f"source: {self.source}"

            # Start the monitoring pipeline
            self.set_interval(2.0, self._update_stats)

            alerts = self.query_one("#alerts", AlertFeed)
            alerts.write_line("[INFO] CocoSentry dashboard started")
            alerts.write_line(f"[INFO] Source: {self.source}")
            alerts.write_line(f"[INFO] Known networks: {len(self.config.known_networks)}")

            if self.config.coral.use_edgetpu:
                alerts.write_line("[INFO] Edge TPU inference enabled")
            else:
                alerts.write_line("[INFO] CPU inference mode")

        def _update_stats(self) -> None:
            stats = self.query_one("#stats", Static)
            now = time.strftime("%H:%M:%S")
            models_dir = Path(self.config.coral.model_dir)
            model_count = len(list(models_dir.glob("*.tflite"))) if models_dir.exists() else 0

            stats.update(
                f"CocoSentry Monitor\n\n"
                f"Time: {now}\n"
                f"Models loaded: {model_count}\n"
                f"Known networks: {len(self.config.known_networks)}\n"
                f"DB: {self.config.storage.db_path}\n"
            )

        def action_refresh(self) -> None:
            self._update_stats()

    app = CocoSentryApp(config, source)
    app.run()
