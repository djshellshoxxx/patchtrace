# Qt formatting-window recovery

Base `ea16019601486c831941f9bc1a7ba5862a170317`. Recovered donor `c7fb422c750f1d0e5591277b91492874afd79af7` into exact candidate `cbdb6c26c381633b22be51e2403fc88fdefa740a`. The two-file mailbox patch retains the original author. The change filters Qt callbacks before dispatch into the pane formatting controller, retains default QTextBlock state -1 and leaves text, the model, and analysis functionality unchanged.

| Evidence on Linux, PySide6 6.12.0, offscreen | Result |
|---|---|
| Three existing/donor focused cases on base | 1 failed for off-window dispatch, 2 passed |
| All maintained widget tests on exact candidate | 35 passed |
| Fresh editable QPlainTextEdit controls, plain synthetic text | 2 passed. Scrolling the first pane formats its newly visible text, while the other pane stays at its initial window. Editing a visible line clears stale formatting, undo restores it and preserves the exact document text. Dropping the model clears old formatting. |
| Independent replay by CI reviewer | 37/37 passed on candidate. Off-window regression failed on base. |
| Two 3,000-row panes, Qt callbacks entering controller.spans | Base 442 in-window + 5,780 out-of-window. Candidate 442 in-window + 0 out-of-window. Qt itself continues to notify the Python highlighter for bulk-loaded blocks. |
| 65,000-row load, one run of the maintained fixture | Base 0.7791 s. Candidate 0.7099 s. The measurement starts after constructing the synthetic pair. |
| Paired enabling/disabling experiment on candidate, same text, fresh panes, 3 per condition | Disabled median 0.27050 s. Enabled median 0.63049 s. Difference 0.35999 s for the two-pane load. |
| Full-tree Ruff and Git diff whitespace | Passed |

The design measured about 150 ms of added highlighter cost at 65,000 lines and proposed a 450 ms threshold. The maintained regression instead tests total setup/first format against 1.8 s (450 ms multiplied by four for shared runners). The local enabled-versus-disabled median difference was below 450 ms. These small offscreen measurements do not establish native Windows interactive latency or a portable performance guarantee.
