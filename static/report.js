document.addEventListener('DOMContentLoaded', () => {
  const rate = document.getElementById('rate');
  if (!rate) return;
  rate.addEventListener('input', event => {
    const value = Number(event.target.value);
    document.querySelectorAll('.bytes').forEach(cell => {
      cell.nextElementSibling.textContent = '$' + (Number(cell.dataset.bytes) / 1e9 * value).toFixed(4);
    });
  });
});
