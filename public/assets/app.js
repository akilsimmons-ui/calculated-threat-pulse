'use strict';
(function () {
  const search = document.querySelector('#search');
  if (search) {
    const alerts = [...document.querySelectorAll('.threat-card')];
    const count = document.querySelector('#count');
    function filter() {
      const query = search.value.trim().toLowerCase();
      let visible = 0;
      for (const card of alerts) {
        const match = card.dataset.search.includes(query);
        card.classList.toggle('hidden', !match);
        visible += Number(match);
      }
      if (count) count.textContent = visible + ' shown';
    }
    search.addEventListener('input', filter);
    filter();
  }
  const downtimeresult = document.querySelector('#downtime-result');
  const passwordresult = document.querySelector('#password-result');
  if (downtimeresult) {
    const inputs = ['workers', 'hourly', 'hours', 'revenue'].map(id => document.getElementById(id));
    function calculate() {
      const [people, hourly, hours, revenue] = inputs.map(x => Math.max(0, Number(x.value) || 0));
      const impact = Math.min(1e12, people * hourly * hours + revenue * hours);
      downtimeresult.textContent = new Intl.NumberFormat('en-US', {style: 'currency', currency: 'USD', maximumFractionDigits: 0}).format(impact);
    }
    inputs.forEach(i => i.addEventListener('input', calculate));
    calculate();
  }
  if (passwordresult) {
    const chars = document.querySelector('#chars');
    const charset = document.querySelector('#charset');
    function calculate() {
      const length = Math.min(100, Math.max(1, parseInt(chars.value, 10) || 1));
      const bits = length * Math.log2(Number(charset.value));
      passwordresult.textContent = bits.toFixed(1) + ' bits';
    }
    [chars, charset].forEach(i => i.addEventListener('input', calculate));
    calculate();
  }
})();
