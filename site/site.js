// Progressive enhancement only: the page is complete without this file. No network access, no storage.
(() => {
  'use strict';
  document.documentElement.classList.add('js');

  const button = document.querySelector('[data-copy-target]');
  if (!button) return;
  const target = document.getElementById(button.getAttribute('data-copy-target'));
  const status = document.getElementById(button.getAttribute('data-copy-status'));
  if (!target) return;

  const say = (message) => { if (status) status.textContent = message; };
  const select = () => {
    const range = document.createRange();
    range.selectNodeContents(target);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
  };

  // Show the button only where the clipboard API exists; elsewhere the address stays selectable text.
  if (!(navigator.clipboard && typeof navigator.clipboard.writeText === 'function')) return;
  button.hidden = false;
  button.addEventListener('click', () => {
    const text = target.textContent.trim();
    navigator.clipboard.writeText(text).then(
      () => { select(); say('Address copied to the clipboard.'); },
      () => { select(); say('Copy was blocked. The address is selected; press Ctrl+C or Cmd+C.'); }
    );
  });
})();
