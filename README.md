# Cybersecurity Log Analyzer

A small browser tool for reviewing sample server and sign-in logs. It highlights repeated failures, suspicious paths, privilege-related wording, and repeated source IPs, then turns the matches into a simple risk summary.

## Run

Open `index.html` in a browser.

## What It Does

- Accepts pasted or uploaded `.txt` and `.log` files.
- Uses clear rule-based checks instead of hidden scoring.
- Groups findings by source IP where possible.
- Shows matched evidence and response notes.
- Exports a JSON report for later review.

## Safety Note

Use sample logs or logs you are allowed to review. Do not upload real customer, school, or workplace logs unless they have been cleaned first.

## What I Learned

- Small detection rules are easier to trust when the matched evidence is shown beside the result.
- A log tool is more useful when it explains why something was flagged, not just that it was flagged.
- Even a simple browser app needs tidy sample data to feel finished.

## Next Improvements

- Add a few more sample logs for failed sign-ins, web probes, and normal traffic.
- Add a screenshot after the next UI polish pass.
- Add a short manual test checklist for the main rules.
