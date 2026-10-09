const themeButton = document.getElementById("themeToggle");
const themeIcon = document.getElementById("themeIcon");

if (themeButton && themeIcon) {
    const savedTheme = localStorage.getItem("aegistrace-theme");

    if (savedTheme === "light") {
        document.body.classList.add("light-theme");
    }

    function updateThemeIcon() {
        const lightMode =
            document.body.classList.contains("light-theme");

        if (lightMode) {
            themeIcon.textContent = "☾";
            themeButton.title = "Switch to dark mode";
        } else {
            themeIcon.textContent = "☀";
            themeButton.title = "Switch to light mode";
        }
    }

    themeButton.addEventListener("click", function () {
        document.body.classList.toggle("light-theme");

        const lightMode =
            document.body.classList.contains("light-theme");

        localStorage.setItem(
            "aegistrace-theme",
            lightMode ? "light" : "dark"
        );

        updateThemeIcon();
    });

    updateThemeIcon();
}
