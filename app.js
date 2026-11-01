const menuBtn = document.getElementById("menuBtn");
const sidebar = document.getElementById("sidebar");
if (menuBtn && sidebar) {
  menuBtn.addEventListener("click", () => sidebar.classList.toggle("open"));
  document.addEventListener("click", (event) => {
    if (window.innerWidth <= 850 && sidebar.classList.contains("open") &&
        !sidebar.contains(event.target) && !menuBtn.contains(event.target)) {
      sidebar.classList.remove("open");
    }
  });
}
