# Pseudocode

1. Read pasted logs or an uploaded log file.
2. Split the text into clean lines.
3. Run each line through defensive detection rules.
4. Extract source IP addresses when they exist.
5. Group incidents by IP and add risk points.
6. Render the summary, risk label, incident list, IP table, checklist, and response notes.
7. Export the report as JSON after an analysis has been run.

Review note: keep the matched log line visible beside each finding so the score can be checked manually.

