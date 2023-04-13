function toggleContent(button) {
  const targetId = button.getAttribute('data-target');
  const targetElement = document.getElementById(targetId);
  const isHidden = targetElement.style.display === 'none';

  targetElement.style.display = isHidden ? 'block' : 'none';
}
