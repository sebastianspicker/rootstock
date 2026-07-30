import {execFileSync} from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

import {expect, test} from "@playwright/test";

let server: http.Server;
let origin = "";

test.beforeAll(async () => {
  const output = path.join(os.tmpdir(), `rootstock-pages-demo-${process.pid}.html`);
  execFileSync(process.execPath, ["scripts/build-pages-demo.mjs", output]);
  const html = fs.readFileSync(output, "utf8");
  fs.rmSync(output);

  server = http.createServer((_request, response) => {
    response.writeHead(200, {"Content-Type": "text/html; charset=utf-8"});
    response.end(html);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected demo server port");
  origin = `http://127.0.0.1:${address.port}`;
});

test.afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
});

test("published demo discloses its synthetic static behavior", async ({page}) => {
  await page.goto(origin);

  await expect(page.getByLabel("Static demo disclosure")).toContainText(
    "No host collection, server connection, query execution, or graph mutation occurs here.",
  );
  await expect(page.getByLabel("Static demo using a synthetic fixture")).toBeVisible();
  await expect(page.locator("#live-actions")).toBeHidden();
  await expect(page.getByText("Saved queries are available in live mode.")).toBeAttached();

  const simulatedExports = page.getByLabel("Export simulated fixture as PNG");
  await expect(simulatedExports).toHaveCount(2);
  await expect(simulatedExports.last()).toHaveClass(/demo-simulated-action/);
});

test("published demo supports the real static path workflow", async ({page}) => {
  await page.goto(origin);
  await page.getByRole("button", {name: "Build path", exact: true}).click();
  await page.getByRole("button", {name: /Unsigned Helper/}).click();
  await page.getByRole("button", {name: /Shared Credential/}).click();

  await expect(page.getByText("2 hops", {exact: true})).toBeVisible();
  await expect(page.getByRole("heading", {name: "Shared Credential"})).toBeVisible();

  if (test.info().project.name === "desktop") {
    const screenshot = path.resolve("graph/generated/pages-demo/preview-desktop.png");
    fs.mkdirSync(path.dirname(screenshot), {recursive: true});
    await page.screenshot({path: screenshot, animations: "disabled", caret: "hide"});
  }
});

test("published demo keeps its narrow layout within the viewport", async ({page}) => {
  test.skip(test.info().project.name !== "narrow");
  await page.goto(origin);
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
  await expect(page.getByLabel("Static demo disclosure")).toBeVisible();
});
