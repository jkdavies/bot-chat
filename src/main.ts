import { readFileSync } from "node:fs";
import { configSchema } from "./config.js";
import { createApp } from "./server.js";
process.umask(0o077);
try {
  const config = configSchema.parse({
    ...JSON.parse(
      readFileSync(process.env.BOT_CHAT_CONFIG ?? "config.local.json", "utf8"),
    ),
    publicBaseUrl: process.env.PUBLIC_BASE_URL,
  });
  const { app, store } = createApp(config);
  const listener = app.listen(config.port, config.bind, () =>
    console.log("bot-chat listening"),
  );
  const close = () => {
    listener.close(() => {
      store.db.close();
      process.exit(0);
    });
  };
  process.on("SIGTERM", close);
  process.on("SIGINT", close);
} catch {
  console.error("Startup failed. Check configuration and secret file paths.");
  process.exitCode = 1;
}
