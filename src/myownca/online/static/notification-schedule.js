/* Shared Admin/Superuser controls for the application's expiry sweep. */
window.NotificationScheduleControls = (() => {
  const states = new WeakMap();
  const maxSeconds = 2147483647;

  function showSettings(form, settings) {
    form.elements.enabled.checked = settings.enabled;
    const unit = [86400, 3600, 60, 1].find((value) => settings.interval_seconds % value === 0);
    form.elements.unit.value = String(unit);
    form.elements.duration.value = settings.interval_seconds / unit;
    form.elements.duration.max = Math.floor(maxSeconds / unit);
  }

  async function refresh(root) {
    if (!states.has(root)) {
      root.innerHTML = `
        <h2>Automatic rule checks</h2>
        <form>
          <fieldset>
            <label class="checkbox notification-schedule-enabled"><input name="enabled" type="checkbox"> Enable automatic checks</label>
            <label>Check every<input name="duration" type="number" min="1" step="1" required value="1"></label>
            <label>Time unit<select name="unit">
              <option value="1">Seconds</option><option value="60">Minutes</option>
              <option value="3600">Hours</option><option value="86400" selected>Days</option>
            </select></label>
            <button type="submit">Save</button>
          </fieldset>
          <p role="status" aria-live="polite"></p>
        </form>
        <p>Automatic checks look for enabled expiry rules that are due.
          Rules define recipients and timing; templates define the message.</p>
        <p class="hint">Example: checking every minute lets the app find due rules promptly.
          A rule with a seven-day interval still follows that seven-day interval.</p>
        <details>
          <summary>Scheduling details</summary>
          <p>Changes apply immediately without restarting. Enabling checks due rules now;
            disabling allows an active check to finish. Manual checks remain available.</p>
          <p>Disable external notification cron jobs before enabling automatic checks.</p>
        </details>`;
      const form = root.querySelector("form");
      const status = root.querySelector('[role="status"]');
      const fields = root.querySelector("fieldset");
      const state = { form, status, fields, saving: false, dirty: false, loading: null };
      states.set(root, state);
      form.addEventListener("input", () => {
        state.dirty = true;
        form.elements.duration.max = Math.floor(maxSeconds / Number(form.elements.unit.value));
        status.textContent = "Unsaved changes.";
      });
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (state.saving || !form.reportValidity()) return;
        const seconds = Number(form.elements.duration.value) * Number(form.elements.unit.value);
        if (!Number.isSafeInteger(seconds) || seconds < 1 || seconds > maxSeconds) {
          status.textContent = "Enter a positive whole-number duration within the allowed range.";
          return;
        }
        state.saving = true;
        fields.disabled = true;
        status.textContent = "Saving…";
        try {
          const saved = await myOwnCA.api("/internal/notifications/schedule", {
            method: "PUT",
            body: JSON.stringify({ enabled: form.elements.enabled.checked, interval_seconds: seconds }),
          });
          showSettings(form, saved);
          state.dirty = false;
          status.textContent = "Saved. Changes are active; no restart is needed.";
        } catch (error) {
          status.textContent = `Could not confirm the save. Refresh to check saved settings. ${error.message}`;
        } finally {
          state.saving = false;
          fields.disabled = false;
        }
      });
    }
    const state = states.get(root);
    if (state.saving || state.dirty) return;
    if (state.loading) return state.loading;
    // Portal initialization can request this view twice. Share that fetch so
    // a late response cannot overwrite a user's edits or a completed save.
    state.loading = (async () => {
      state.fields.disabled = true;
      state.status.textContent = "Loading schedule…";
      try {
        const saved = await myOwnCA.api("/internal/notifications/schedule");
        showSettings(state.form, saved);
        state.fields.disabled = false;
        state.status.textContent = "";
      } catch (error) {
        state.status.textContent = `Could not load the saved schedule. ${error.message}`;
      }
    })();
    try {
      await state.loading;
    } finally {
      state.loading = null;
    }
  }

  return { refresh };
})();
