import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

describe("forgot-password workflow", () => {
  let originalFetch;
  let originalCyberNotify;
  let handleForgotPasswordSubmit;

  beforeEach(async () => {
    document.body.innerHTML = `
      <form id="forgotPasswordForm">
        <input type="email" name="email" />
        <button type="submit">Send Reset Link</button>
      </form>
    `;

    originalFetch = global.fetch;
    originalCyberNotify = window.CyberNotify;

    window.CyberNotify = { alert: vi.fn() };
    global.fetch = vi.fn();

    vi.resetModules();
    await import("./forgot-password.js");
    handleForgotPasswordSubmit = window.handleForgotPasswordSubmit;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    global.fetch = originalFetch;
    window.CyberNotify = originalCyberNotify;
    document.body.innerHTML = "";
  });

  it("submits email payload and shows success message", async () => {
    const form = document.getElementById("forgotPasswordForm");
    form.querySelector("input[name='email']").value = "user@example.com";
    global.fetch.mockResolvedValue({ ok: true });

    await handleForgotPasswordSubmit({
      preventDefault: vi.fn(),
      currentTarget: form,
    });

    expect(global.fetch).toHaveBeenCalledWith(
      "https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/auth/forget-password",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "Content-Type": "application/json",
          "ngrok-skip-browser-warning": "true",
        }),
        body: JSON.stringify({ email: "user@example.com" }),
      }),
    );
    expect(window.CyberNotify.alert).toHaveBeenCalledWith(
      "If this email is registered, a password reset link has been sent.",
      expect.objectContaining({ type: "success" }),
    );
    expect(form.querySelector("button[type='submit']").textContent).toBe("Check Email");
    expect(form.querySelector("button[type='submit']").disabled).toBe(true);
  });

  it("retries with /forgot-password when /forget-password returns 404", async () => {
    const form = document.getElementById("forgotPasswordForm");
    form.querySelector("input[name='email']").value = "user@example.com";
    global.fetch
      .mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: vi.fn().mockResolvedValue({}),
      })
      .mockResolvedValueOnce({ ok: true });

    await handleForgotPasswordSubmit({
      preventDefault: vi.fn(),
      currentTarget: form,
    });

    expect(global.fetch).toHaveBeenCalledTimes(2);
    expect(global.fetch).toHaveBeenNthCalledWith(
      1,
      "https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/auth/forget-password",
      expect.any(Object),
    );
    expect(global.fetch).toHaveBeenNthCalledWith(
      2,
      "https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/auth/forgot-password",
      expect.any(Object),
    );
    expect(window.CyberNotify.alert).toHaveBeenCalledWith(
      "If this email is registered, a password reset link has been sent.",
      expect.objectContaining({ type: "success" }),
    );
  });

  it("shows warning when email is missing", async () => {
    const form = document.getElementById("forgotPasswordForm");
    form.querySelector("input[name='email']").value = "";

    await handleForgotPasswordSubmit({
      preventDefault: vi.fn(),
      currentTarget: form,
    });

    expect(global.fetch).not.toHaveBeenCalled();
    expect(window.CyberNotify.alert).toHaveBeenCalledWith(
      "Please enter your email address.",
      expect.objectContaining({ type: "warning" }),
    );
  });

  it("returns unified success feedback for 422 responses", async () => {
    const form = document.getElementById("forgotPasswordForm");
    form.querySelector("input[name='email']").value = "user@example.com";
    global.fetch.mockResolvedValue({
      ok: false,
      status: 422,
      json: vi.fn().mockResolvedValue({ message: "The selected email is invalid." }),
    });

    await handleForgotPasswordSubmit({
      preventDefault: vi.fn(),
      currentTarget: form,
    });

    expect(window.CyberNotify.alert).toHaveBeenCalledWith(
      "If this email is registered, a password reset link has been sent.",
      expect.objectContaining({ type: "success" }),
    );
    expect(form.querySelector("button[type='submit']").textContent).toBe("Check Email");
    expect(form.querySelector("button[type='submit']").disabled).toBe(true);
  });
});
