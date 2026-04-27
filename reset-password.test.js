import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

describe("reset-password workflow", () => {
  let originalFetch;
  let originalCyberNotify;
  let parseResetParams;
  let handleResetPasswordSubmit;

  beforeEach(async () => {
    document.body.innerHTML = `
      <form id="resetPasswordForm">
        <input name="email" type="email" />
        <input name="token" type="hidden" />
        <input name="new_password" type="password" />
        <input name="password_confirmation" type="password" />
        <button type="submit">Update Password</button>
      </form>
    `;

    originalFetch = global.fetch;
    originalCyberNotify = window.CyberNotify;
    window.CyberNotify = { alert: vi.fn() };
    global.fetch = vi.fn();
    window.history.replaceState({}, "", "/reset-password.html?token=abc&email=user%40example.com");

    vi.useFakeTimers();
    vi.resetModules();
    await import("./reset-password.js");
    parseResetParams = window.parseResetParams;
    handleResetPasswordSubmit = window.handleResetPasswordSubmit;
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    global.fetch = originalFetch;
    window.CyberNotify = originalCyberNotify;
    document.body.innerHTML = "";
  });

  it("parses token and email from URL query", () => {
    const parsed = parseResetParams("?token=test-token&email=test%40example.com");
    expect(parsed).toEqual({ token: "test-token", email: "test@example.com" });
  });

  it("blocks submit when passwords do not match", async () => {
    const form = document.getElementById("resetPasswordForm");
    form.querySelector("input[name='email']").value = "user@example.com";
    form.querySelector("input[name='token']").value = "abc";
    form.querySelector("input[name='new_password']").value = "Password123!";
    form.querySelector("input[name='password_confirmation']").value = "Password321!";

    await handleResetPasswordSubmit({ preventDefault: vi.fn(), currentTarget: form });

    expect(global.fetch).not.toHaveBeenCalled();
    expect(window.CyberNotify.alert).toHaveBeenCalledWith(
      "Passwords do not match. Please re-enter both fields.",
      { type: "warning" }
    );
  });

  it("sends strict payload and redirects after success", async () => {
    const form = document.getElementById("resetPasswordForm");
    form.querySelector("input[name='email']").value = "user@example.com";
    form.querySelector("input[name='token']").value = "abc";
    form.querySelector("input[name='new_password']").value = "Password123!";
    form.querySelector("input[name='password_confirmation']").value = "Password123!";
    global.fetch.mockResolvedValue({ ok: true });

    await handleResetPasswordSubmit({ preventDefault: vi.fn(), currentTarget: form });

    expect(global.fetch).toHaveBeenCalledWith(
      "https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/auth/reset-password",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "Content-Type": "application/json",
          "ngrok-skip-browser-warning": "true"
        }),
        body: JSON.stringify({
          token: "abc",
          email: "user@example.com",
          password: "Password123!",
          password_confirmation: "Password123!"
        })
      })
    );
    expect(window.CyberNotify.alert).toHaveBeenCalledWith(
      "Password updated successfully. Redirecting to login...",
      { type: "success" }
    );

    vi.advanceTimersByTime(3000);
    expect(window.location.href.endsWith("/login.html")).toBe(true);
  });

  it("shows backend validation message for 422", async () => {
    const form = document.getElementById("resetPasswordForm");
    form.querySelector("input[name='email']").value = "user@example.com";
    form.querySelector("input[name='token']").value = "abc";
    form.querySelector("input[name='new_password']").value = "short";
    form.querySelector("input[name='password_confirmation']").value = "short";
    global.fetch.mockResolvedValue({
      ok: false,
      status: 422,
      json: vi.fn().mockResolvedValue({ errors: { password: ["Password must be at least 8 characters"] } })
    });

    await handleResetPasswordSubmit({ preventDefault: vi.fn(), currentTarget: form });

    expect(window.CyberNotify.alert).toHaveBeenCalledWith(
      "Password must be at least 8 characters",
      { type: "error" }
    );
  });
});
