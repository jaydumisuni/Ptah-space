/*
 * Example project adapter for Ptah Visual Device Verification Lab.
 *
 * Copy this file to <project-id>.adapter.mjs and keep project-specific selectors,
 * navigation and setup here. Do not put those details into capture.mjs.
 */
export async function prepare(page, context) {
  const { scene } = context;

  switch (scene.id) {
    case "baseline":
      return;

    // Example:
    // case "comments-keyboard":
    //   await page.getByRole("button", { name: "Notes" }).click();
    //   await page.getByRole("button", { name: "Comment" }).click();
    //   await page.getByRole("textbox").fill("visual proof draft");
    //   return;

    default:
      throw new Error(`Adapter does not implement scene '${scene.id}'. Missing evidence must remain explicit.`);
  }
}
