import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const requiredFiles = [
  "index.html",
  "app.js",
  "styles.css",
  "README.md",
  "PSEUDOCODE.md",
  "screenshots/app-home.png"
];

for (const file of requiredFiles) {
  if (!fs.existsSync(path.join(root, file))) {
    throw new Error(`Missing required file: ${file}`);
  }
}

const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
for (const heading of ["## Run", "## Screenshot", "## Testing", "## Safety Note"]) {
  if (!readme.includes(heading)) {
    throw new Error(`README is missing ${heading}`);
  }
}

const banned = [
  new RegExp("GitHub " + "upload", "i"),
  new RegExp("ready to be " + "uploaded", "i"),
  new RegExp("AI " + "generated", "i"),
  new RegExp("Chat" + "GPT", "i"),
  new RegExp("ghp_" + "\\.\\.\\.", "i"),
  new RegExp("sk_" + "test_", "i"),
  new RegExp("whsec" + "_", "i")
];
const filesToCheck = ["README.md", "index.html", "app.js", "PSEUDOCODE.md"];
for (const file of filesToCheck) {
  const text = fs.readFileSync(path.join(root, file), "utf8");
  for (const pattern of banned) {
    if (pattern.test(text)) {
      throw new Error(`${file} contains blocked wording: ${pattern}`);
    }
  }
}

const html = fs.readFileSync(path.join(root, "index.html"), "utf8");
if (!html.includes('<script src="app.js"></script>')) {
  throw new Error("index.html does not load app.js");
}
