import { describe, expect, it } from "vitest";
import { readCookie } from "./cookies";

describe("readCookie", () => {
  it("finds a cookie among several", () => {
    expect(readCookie("csrftoken", "a=1; csrftoken=abc%20def; b=2")).toBe("abc def");
  });
  it("returns null when absent", () => {
    expect(readCookie("csrftoken", "a=1")).toBeNull();
  });
  it("keeps '=' inside values", () => {
    expect(readCookie("t", "t=a=b")).toBe("a=b");
  });
});
