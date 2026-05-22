// Enables the "Delete account permanently" button only when the user has
// typed the exact confirmation phrase. Wired via oninput= on the input.

function deleteAccountInput(input) {
  const btn = document.getElementById('btn-delete');
  const expected = 'delete ' + (input.dataset.email || '');
  if (btn) btn.disabled = input.value !== expected;
}
