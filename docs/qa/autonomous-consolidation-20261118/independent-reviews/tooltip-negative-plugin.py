import os
import pytest

@pytest.fixture(autouse=True)
def remove_inventory_tooltip(monkeypatch):
    from patchtrace.kbcorrelation.inventory_qt import InventoryDialog
    original = InventoryDialog.__init__
    def construct(self, *args, **kwargs):
        original(self, *args, **kwargs)
        getattr(self, os.environ['PATCHTRACE_TOOLTIP_NEGATIVE']).setToolTip('')
    monkeypatch.setattr(InventoryDialog, '__init__', construct)
