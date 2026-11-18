"""Core engine: high-level facade for scan orchestration and asset management.

The engine ties together the scanner and the database and provides a module
registration point for collectors, so new platforms/connectors can be added
without changing the scan flow.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple

from mijhar.core.config import Config, Platform, get_config
from mijhar.core.scanner import ScanResult, Scanner
from mijhar.database.models import Database

CollectorFactory = Callable[..., object]


class Engine:
    """Application facade used by the CLI and future integrations."""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or get_config()
        self.scanner = Scanner(config=self.config)
        self._collectors: Dict[Tuple[str, str], CollectorFactory] = {}

    # -- module registration ------------------------------------------------

    def register_collector(self, target: str, platform: Platform, factory: CollectorFactory) -> None:
        """Register a collector factory for a (target, platform) combination."""
        self._collectors[(target, platform.value)] = factory

    def has_collector(self, target: str, platform: Platform) -> bool:
        return (target, platform.value) in self._collectors

    # -- scan execution -----------------------------------------------------

    def run_scan(
        self,
        platform: Platform,
        target: str = "local",
        asset_id: Optional[str] = None,
        **collector_kwargs,
    ) -> ScanResult:
        return self.scanner.run(
            platform,
            target=target,
            asset_id=asset_id,
            collector_kwargs=collector_kwargs,
        )

    # -- asset management / history ----------------------------------------

    def list_assets(self) -> List[dict]:
        with Database(self.config.db_path) as db:
            return db.list_assets()

    def history(self, limit: int = 20) -> List[dict]:
        return self.scanner.list_scans(limit=limit)

    def results(self, scan_id: Optional[str] = None) -> dict:
        resolved = scan_id or self.scanner.latest_scan_id()
        if resolved is None:
            raise ValueError("no scans found")
        return self.scanner.build_report_data(resolved)
