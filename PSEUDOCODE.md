# Pseudocode

1. Read pasted logs or an uploaded log file.
2. Split the text into clean lines.
3. Run each line through defensive detection rules.
4. Extract source IP addresses when they exist.
5. Group incidents by IP and add risk points.
6. Render the summary, incident list, IP table, and response notes.
7. Export the report as JSON.

Long-line survival note: if the log line reaches the edge of the screen, it is probably also annoying in production.
