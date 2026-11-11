# Exploitation context panel

The **Exploitation context** panel looks up CVE IDs in a CISA Known Exploited Vulnerabilities (KEV) catalog that is stored on your computer. Its title is `Exploitation context`. It is a right dock, shown with `Ctrl+Shift+X`, and it is tabbed with **KB and CVE**.

KEV membership is context about a CVE. It is not a property of a function, and it does not change any ranking or match.

Type CVE IDs in **CVE IDs to look up** and choose **Look up**. Results are filtered with a choice of:

- `All CVEs`
- `Listed in KEV`
- `Listed, ransomware use known`
- `Not listed`
- `No catalog or invalid ID`

Sort with `Input order`, or with `KEV-listed first (reading order, not a score)`. The second option only changes reading order.

Catalog controls:

- **Update from CISA...** shows the exact request first. The request is sent only after you approve it. **Cancel without contacting CISA** cancels before any request.
- **Import file...** reads a catalog JSON file you saved. It works even when network updates are off.
- **Show changes** compares the two newest stored catalogs.
- **Copy**, **Copy address** and **Go to CVE context** copy the record, copy the CISA page address, and go to the CVE context.

When network updates are off in your setup, the panel says: *Network updates are switched off here. Import file still works.*

Read the catalog's source and date with every answer. Source labels are `CISA website`, `CISA GitHub mirror` or `a local file`. A catalog that is absent, old or unreadable cannot support a current negative answer. `Not listed` applies only to the snapshot you checked. The due date shown in a record is CISA's, not a judgement about your obligations.

The same catalog is available from the command line: [`patchtrace kev`](68-cli-kev.md).

Sources: `src/patchtrace/kev/panel.py`, `src/patchtrace/ui_kev.py`, `src/patchtrace/kev/view_model.py`, `src/patchtrace/kev/cli.py`.
