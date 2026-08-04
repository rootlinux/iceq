import { expect, test } from "@playwright/test";

test("attachment grants can schedule and clear their timeout in the browser", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));

  await page.goto("/login");

  const calls = await page.evaluate(async () => {
    const modulePath = "/src/lib/attachmentGrantLifecycle.ts";
    const module = await import(/* @vite-ignore */ modulePath);
    const AttachmentGrantLifecycle = module.AttachmentGrantLifecycle as new (deps: {
      grant: (objectKey: string, granteeUin: number) => Promise<void>;
      revoke: (objectKey: string, granteeUin: number) => Promise<void>;
      retryDelaysMs: number[];
    }) => {
      prepare(messageId: string, objectKey: string, granteeUin: number): Promise<void>;
      ack(messageId: string, status: "persisted"): void;
      revokeAll(): Promise<void>;
    };

    const observedCalls: string[] = [];
    const lifecycle = new AttachmentGrantLifecycle({
      grant: async (objectKey, granteeUin) => {
        observedCalls.push(`grant:${objectKey}:${granteeUin}`);
      },
      revoke: async (objectKey, granteeUin) => {
        observedCalls.push(`revoke:${objectKey}:${granteeUin}`);
      },
      retryDelaysMs: [],
    });

    await lifecycle.prepare("pdf-message", "pdf-object", 200);
    lifecycle.ack("pdf-message", "persisted");
    await lifecycle.revokeAll();
    return observedCalls;
  });

  expect(calls).toEqual(["grant:pdf-object:200"]);
  expect(pageErrors).toEqual([]);
});
