import { Cron } from "croner";
import { getSettings } from "./db";
import { refreshKev } from "./vuln/kev";

let job: Cron | null = null;

export function scheduleWild() {
  job?.stop();
  const sec = Math.max(60, getSettings().wildRefreshSec);
  job = new Cron("* * * * * *", { interval: sec, protect: true, name: "prohori-kev", startAt: new Date(Date.now() + sec * 1000) }, () => {
    void refreshKev("scheduled");
  });
}
