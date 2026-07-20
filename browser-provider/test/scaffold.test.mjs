import assert from "node:assert/strict";
import test from "node:test";
import { scaffoldStatus } from "../src/index.mjs";

test("browser provider scaffold cannot claim runtime authorization", () => {
  assert.equal(scaffoldStatus.runtimeAuthorized, false);
});
