Unified panel
Experimental. The reviewed source contains the Unified panel declaration, controller, and read model. Its derived decisions are rule-based and uncalibrated. Packaged availability is UNVERIFIED.
Use Ctrl+Shift+U when available. Unified combines stored engine evidence into a derived view while retaining each engine’s native values in separate columns.
Run unified analysis requires an open project, a finished Ghidriff run, no competing job, and the documented unified/enabled setting. It writes a derived result without replacing the primary Ghidriff comparison.
Use the pairing-decision, change-classification, change-class, and source filters to narrow the table. Search accepts function names and hexadecimal addresses. Unchanged and structurally cosmetic rows are collapsed by default; the summary retains their counts. The corresponding display control reveals them.
Select a row to inspect support, contest, change facts, limitations, and provenance. Open it in the code panes before interpreting the classification. A correction is available only when the row maps to a Ghidriff match.
Copy provenance copies selected rows. Explain previews bounded descriptive text; that preview does not transmit it.
If extraction is unavailable, the result can use stored engine outputs without instruction-level change facts. Read that notice before drawing conclusions from missing detail.
A partial result has incomplete evidence. A stale result describes changed inputs. Run again when a current result is needed. Cancellation leaves the previous result current rather than publishing unfinished work.
Sources: src/patchtrace/unified/panel.py; src/patchtrace/unified/read_model.py; src/patchtrace/ui_unified.py.
