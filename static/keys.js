'use strict';

function randomHex(byteCount) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteCount));
  return [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
}

for (const panel of document.querySelectorAll('[data-keygen]')) {
  panel.querySelector('[data-generate]').addEventListener('click', () => {
    panel.querySelector('[data-password]').value = randomHex(14);
    panel.querySelector('[data-signing-key]').value = randomHex(32);
    panel.querySelector('[data-values]').hidden = false;
  });
  for (const field of panel.querySelectorAll('input[readonly]')) {
    field.addEventListener('click', () => field.select());
  }
}
