import { loadConfig } from "./config.js";
import { createApp } from "./app.js";

const config = loadConfig();
const app = createApp(config);

app.listen(config.port, () => {
  process.stderr.write(`[gateway] Listening on port ${config.port}\n`);
});
