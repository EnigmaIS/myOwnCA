const loginForm = document.querySelector("#login-form");
const passwordRecoveryRequestForm = document.querySelector("#password-recovery-request-form");
const passwordRecoveryVerifyForm = document.querySelector("#password-recovery-verify-form");
const passwordChangeForm = document.querySelector("#password-change-form");
const totpEnrollPanel = document.querySelector("#totp-enroll-panel");
const totpEnrollForm = document.querySelector("#totp-enroll-form");
const totpChallengeForm = document.querySelector("#totp-challenge-form");
const recoveryPanel = document.querySelector("#recovery-panel");
const recoveryCodeForm = document.querySelector("#recovery-code-form");
const recoveryDeliveryForm = document.querySelector("#recovery-delivery-form");
const recoveryCodesPanel = document.querySelector("#recovery-codes-panel");
const authError = document.querySelector("#auth-error");
let csrfToken = null;
let passwordRecoveryContext = null;
let recoveryChannels = [];

const channelLabels = {
  email: "Email",
  sms: "SMS",
  slack: "Slack",
  webhook: "Webhook",
  https: "HTTPS integration",
};

async function authRequest(path, options = {}) {
  const response = await fetch(path, {
    headers: {
      "Content-Type": "application/json",
      ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
      ...(options.headers || {}),
    },
    ...options,
  });
  const responseText = response.status === 204 ? "" : await response.text();
  let body = null;
  if (responseText) {
    try {
      body = JSON.parse(responseText);
    } catch {
      throw new Error(
        response.ok
          ? `Unexpected non-JSON response (${response.status})`
          : `Request failed with ${response.status} ${response.statusText}`,
      );
    }
  }
  if (!response.ok) {
    const detail = body?.detail ?? body?.error ?? body?.message;
    if (Array.isArray(detail)) {
      throw new Error(detail.map((item) => item?.msg || JSON.stringify(item)).join("; "));
    }
    throw new Error(detail || `Request failed with ${response.status}`);
  }
  return body;
}

function clearAuthError() {
  if (!authError) return;
  authError.textContent = "";
  authError.hidden = true;
}

function showAuthError(error) {
  if (!authError) return;
  authError.textContent = error?.message || String(error) || "Authentication failed";
  authError.hidden = false;
}

async function runAuthAction(action) {
  clearAuthError();
  try {
    return await action();
  } catch (error) {
    showAuthError(error);
    return null;
  }
}

function formPayload(form) {
  return Object.fromEntries(new FormData(form).entries());
}

function showStage(body) {
  csrfToken = body.csrf_token;
  // Redirect before touching stage-specific elements. This also keeps login
  // working when a browser briefly has mismatched cached HTML and JavaScript.
  if (body.stage === "active") {
    window.location.replace("/app");
    return;
  }
  loginForm?.classList.add("hidden");
  passwordRecoveryRequestForm?.classList.add("hidden");
  passwordRecoveryVerifyForm?.classList.add("hidden");
  recoveryCodesPanel?.classList.add("hidden");
  const passwordStage = ["password_change_required", "password_recovery_required"].includes(body.stage);
  passwordChangeForm?.classList.toggle("hidden", !passwordStage);
  const passwordTitle = document.querySelector("#password-change-title");
  if (passwordTitle) {
    passwordTitle.textContent = body.stage === "password_recovery_required"
      ? "Set a new password"
      : "Choose a new password";
  }
  const passwordDescription = document.querySelector("#password-change-description");
  if (passwordDescription) {
    passwordDescription.textContent = body.stage === "password_recovery_required"
      ? "The recovery code was accepted. Saving this password will revoke other sessions and reset TOTP when your role requires it."
      : "Temporary passwords must be replaced before continuing.";
  }
  totpEnrollPanel?.classList.toggle("hidden", body.stage !== "totp_enrollment_required");
  totpChallengeForm?.classList.toggle("hidden", body.stage !== "totp_required");
  recoveryPanel?.classList.toggle("hidden", body.stage !== "totp_required");
  recoveryDeliveryForm?.classList.add("hidden");
}

async function showRecoveryCodes() {
  // Called after enrollment completes; show one-time codes before entering the app.
  loginForm?.classList.add("hidden");
  passwordRecoveryRequestForm?.classList.add("hidden");
  passwordRecoveryVerifyForm?.classList.add("hidden");
  passwordChangeForm?.classList.add("hidden");
  totpEnrollPanel?.classList.add("hidden");
  totpChallengeForm?.classList.add("hidden");
  recoveryPanel?.classList.add("hidden");
  try {
    const body = await authRequest("/internal/auth/recovery/codes/regenerate", { method: "POST" });
    document.querySelector("#recovery-codes").textContent = body.recovery_codes.join("\n");
    recoveryCodesPanel.classList.remove("hidden");
  } catch (_) {
    window.location.assign("/app");
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await runAuthAction(async () => {
    const body = await authRequest("/internal/auth/login", {
      method: "POST",
      body: JSON.stringify(formPayload(event.currentTarget)),
    });
    showStage(body);
    if (body.stage === "totp_enrollment_required") {
      await beginEnrollment();
    }
  });
});

document.querySelector("#forgot-password")?.addEventListener("click", () => {
  clearAuthError();
  loginForm.classList.add("hidden");
  passwordRecoveryRequestForm.classList.remove("hidden");
  passwordRecoveryRequestForm.elements.email.value = loginForm.elements.email.value;
});

document.querySelector("#password-recovery-cancel")?.addEventListener("click", () => {
  clearAuthError();
  passwordRecoveryRequestForm.classList.add("hidden");
  loginForm.classList.remove("hidden");
});

document.querySelector("#password-recovery-restart")?.addEventListener("click", () => {
  clearAuthError();
  passwordRecoveryVerifyForm.classList.add("hidden");
  passwordRecoveryRequestForm.classList.remove("hidden");
});

passwordRecoveryRequestForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  await runAuthAction(async () => {
    const payload = formPayload(event.currentTarget);
    await authRequest("/internal/auth/password/recovery/request", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    passwordRecoveryContext = payload;
    passwordRecoveryRequestForm.classList.add("hidden");
    passwordRecoveryVerifyForm.classList.remove("hidden");
  });
});

passwordRecoveryVerifyForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!passwordRecoveryContext) return;
  await runAuthAction(async () => {
    const body = await authRequest("/internal/auth/password/recovery/verify", {
      method: "POST",
      body: JSON.stringify({ ...passwordRecoveryContext, ...formPayload(event.currentTarget) }),
    });
    showStage(body);
  });
});

passwordChangeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await runAuthAction(async () => {
    const body = await authRequest("/internal/auth/password/change", {
      method: "POST",
      body: JSON.stringify(formPayload(event.currentTarget)),
    });
    showStage(body);
    if (body.stage === "totp_enrollment_required") {
      await beginEnrollment();
    }
  });
});

totpEnrollForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await runAuthAction(async () => {
    const body = await authRequest("/internal/auth/totp/enroll/confirm", {
      method: "POST",
      body: JSON.stringify(formPayload(event.currentTarget)),
    });
    if (body.stage === "active") {
      csrfToken = body.csrf_token;
      await showRecoveryCodes();
    } else {
      showStage(body);
    }
  });
});

totpChallengeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await runAuthAction(async () => {
    const body = await authRequest("/internal/auth/totp/challenge", {
      method: "POST",
      body: JSON.stringify(formPayload(event.currentTarget)),
    });
    showStage(body);
  });
});

recoveryCodeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await runAuthAction(async () => {
    const body = await authRequest("/internal/auth/recovery/code", {
      method: "POST",
      body: JSON.stringify(formPayload(event.currentTarget)),
    });
    showStage(body);
  });
});

document.querySelector("#recovery-delivery-request")?.addEventListener("click", async () => {
  await runAuthAction(async () => {
    const channel = document.querySelector("#totp-recovery-channel").value;
    await authRequest("/internal/auth/recovery/delivery/request", {
      method: "POST",
      body: JSON.stringify({ channel }),
    });
    recoveryDeliveryForm.classList.remove("hidden");
  });
});

recoveryDeliveryForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  await runAuthAction(async () => {
    const body = await authRequest("/internal/auth/recovery/delivery/verify", {
      method: "POST",
      body: JSON.stringify({
        channel: document.querySelector("#totp-recovery-channel").value,
        ...formPayload(event.currentTarget),
      }),
    });
    showStage(body);
    if (body.stage === "totp_enrollment_required") {
      await beginEnrollment();
    }
  });
});

document.querySelector("#recovery-codes-continue")?.addEventListener("click", () => {
  window.location.assign("/app");
});

async function beginEnrollment() {
  const body = await authRequest("/internal/auth/totp/enroll", { method: "POST" });
  if (body.qr_svg) document.querySelector("#totp-qr").src = body.qr_svg;
  document.querySelector("#totp-secret").textContent = body.secret;
  document.querySelector("#totp-uri").textContent = body.provisioning_uri;
}

async function resumeIncompleteSession() {
  try {
    const body = await authRequest("/internal/auth/me");
    showStage(body);
    if (body.stage === "totp_enrollment_required") {
      await beginEnrollment();
    }
  } catch (_) {
    loginForm.classList.remove("hidden");
  }
}

async function loadRecoveryChannels() {
  try {
    const response = await fetch("/internal/auth/recovery/channels");
    if (!response.ok) throw new Error("Recovery channel status unavailable");
    recoveryChannels = (await response.json()).channels || [];
  } catch {
    recoveryChannels = [];
  }
  document.querySelectorAll(".recovery-channel-select").forEach((select) => {
    select.textContent = "";
    recoveryChannels.forEach((channel) => {
      const option = document.createElement("option");
      option.value = channel;
      option.textContent = channelLabels[channel] || channel;
      select.append(option);
    });
    select.disabled = recoveryChannels.length === 0;
  });
  const passwordRecoverySubmit = passwordRecoveryRequestForm?.querySelector('button[type="submit"]');
  if (passwordRecoverySubmit) passwordRecoverySubmit.disabled = recoveryChannels.length === 0;
  const recoveryDeliveryRequest = document.querySelector("#recovery-delivery-request");
  if (recoveryDeliveryRequest) recoveryDeliveryRequest.disabled = recoveryChannels.length === 0;
  document.querySelector("#password-recovery-unavailable")?.classList.toggle(
    "hidden",
    recoveryChannels.length !== 0,
  );
}

loadRecoveryChannels();
resumeIncompleteSession();

// Reveal the "Request a certificate" link only when self-service requests are enabled.
(async () => {
  try {
    const res = await fetch("/access-request/config");
    if (res.ok && (await res.json()).enabled) {
      document.querySelector("#request-access-hint")?.removeAttribute("hidden");
    }
  } catch {
    /* leave hidden — fail closed */
  }
})();
