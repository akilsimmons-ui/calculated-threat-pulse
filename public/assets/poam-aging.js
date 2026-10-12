'use strict';
/* Private-by-design POA&M date arithmetic. No network, storage, or external libraries. */
(function () {
  const form = document.getElementById('poam-aging-form');
  const finding = document.getElementById('poam-opened');
  const target = document.getElementById('poam-target');
  const result = document.getElementById('poam-aging-result');
  if (!form || !finding || !target || !result) return;

  const MILLIS_PER_DAY = 86400000;
  function parseCalendarDay(value) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
    const [year, month, day] = value.split('-').map(Number);
    const utc = new Date(Date.UTC(year, month - 1, day));
    if (utc.getUTCFullYear() !== year || utc.getUTCMonth() !== month - 1 ||
        utc.getUTCDate() !== day) return null;
    return Date.UTC(year, month - 1, day) / MILLIS_PER_DAY;
  }

  function todayAsDay() {
    const now = new Date();
    return Date.UTC(now.getFullYear(), now.getMonth(), now.getDate()) / MILLIS_PER_DAY;
  }

  function update() {
    const opened = parseCalendarDay(finding.value);
    const due = parseCalendarDay(target.value);
    if (opened === null || due === null) {
      result.textContent = 'Choose a valid finding date and target completion date.';
      return;
    }
    const today = todayAsDay();
    if (opened > today) {
      result.textContent = 'The finding date is in the future. Please correct it.';
      return;
    }
    if (due < opened) {
      result.textContent = 'The target date is earlier than the finding date. Please correct it.';
      return;
    }
    const age = today - opened;
    const remaining = due - today;
    const ageLabel = age === 1 ? 'day' : 'days';
    let deadline;
    if (remaining < 0) {
      const behind = Math.abs(remaining);
      deadline = 'Target date overdue by ' + behind + ' ' + (behind === 1 ? 'day' : 'days');
    } else if (remaining === 0) {
      deadline = 'Target completion date is today';
    } else {
      deadline = remaining + ' ' + (remaining === 1 ? 'day' : 'days') + ' until target completion';
    }
    result.textContent = 'Open for ' + age + ' ' + ageLabel + '. ' + deadline + '.';
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    update();
  });
  [finding, target].forEach(function (input) {
    input.addEventListener('change', update);
    input.addEventListener('input', update);
  });

  const now = new Date();
  finding.value = [now.getFullYear(), String(now.getMonth() + 1).padStart(2, '0'),
                   String(now.getDate()).padStart(2, '0')].join('-');
  result.textContent = 'Set a target date to calculate open-item age and remaining days.';
})();
