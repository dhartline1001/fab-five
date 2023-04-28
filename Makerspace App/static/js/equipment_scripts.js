
  function toggleContent(button) {
    const targetId = button.getAttribute('data-target');
    const targetElement = document.getElementById(targetId);
    const isHidden = targetElement.style.display === 'none';

    targetElement.style.display = isHidden ? 'block' : 'none';
  }

      // Get the modal element
    var modal = document.getElementById("modal01");

    // Function to open the modal with the clicked image and caption
    function openModal(imgElement, captionText) {
      var modalImg = document.getElementById("img01");
      var caption = document.getElementById("caption");

      modal.style.display = "block";
      modalImg.src = imgElement.src;
      caption.innerHTML = captionText;
    }

    // Get all the images with class 'equipment-card-img'
    var images = document.getElementsByClassName("equipment-card-img");

    // Attach click event listeners to all the images
    for (var i = 0; i < images.length; i++) {
      images[i].addEventListener("click", function() {
        openModal(this, this.alt);
      });
    }
